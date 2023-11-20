//! Bridge between a local provider and a remote server.
use crate::client::{
    net::{MaybeRetry, RpcClient},
    Error, Result,
};

use async_trait::async_trait;
use http::StatusCode;

use sos_sdk::{
    account::AccountStatus,
    commit::{CommitHash, CommitProof},
    decode,
    events::{Patch, WriteEvent},
    mpc::Keypair,
    signer::ecdsa::BoxedEcdsaSigner,
    url::Url,
    vault::{Summary, VaultId},
    vfs,
};

use std::{any::Any, collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

use crate::{
    client::{LocalProvider, RemoteSync, SyncError},
    retry,
};

use tracing::{span, Level};

/// Remote origin information.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Origin {
    /// Name of the origin.
    pub name: String,
    /// URL of the remote server.
    pub url: Url,
    /// Public key of the remote server.
    pub public_key: Vec<u8>,
}

/// Remote synchronization target.
pub type Remote = Box<dyn RemoteSync>;

/// Collection of remote targets for synchronization.
pub type Remotes = HashMap<Origin, Remote>;

/// Bridge between a local provider and a remote.
#[derive(Clone)]
pub struct RemoteBridge {
    /// Local provider.
    local: Arc<RwLock<LocalProvider>>,
    /// Client to use for remote communication.
    remote: RpcClient,
}

impl RemoteBridge {
    /// Create a new remote bridge that wraps the given
    /// local provider.
    pub fn new(
        local: Arc<RwLock<LocalProvider>>,
        origin: Origin,
        signer: BoxedEcdsaSigner,
        keypair: Keypair,
    ) -> Result<Self> {
        let remote =
            RpcClient::new(origin.url, origin.public_key, signer, keypair)?;
        Ok(Self { local, remote })
    }

    /// Clone of the local provider.
    pub fn local(&self) -> Arc<RwLock<LocalProvider>> {
        Arc::clone(&self.local)
    }
}

/// Sync helper functions.
impl RemoteBridge {
    /// Perform the noise protocol handshake.
    pub async fn handshake(&self) -> Result<()> {
        Ok(self.remote.handshake().await?)
    }

    /// Get account status from remote.
    pub async fn account_status(&self) -> Result<AccountStatus> {
        let (_, status) =
            retry!(|| self.remote.account_status(), self.remote);
        status.ok_or(Error::NoAccountStatus)
    }

    /// Create an account on the remote.
    async fn create_account(&self, buffer: Vec<u8>) -> Result<()> {
        let (status, _) = retry!(
            || self.remote.create_account(buffer.clone()),
            self.remote
        );
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;
        Ok(())
    }

    /// Import a vault into an account that already exists on the remote.
    async fn import_vault(&self, buffer: &[u8]) -> Result<()> {
        let (status, _) =
            retry!(|| self.remote.create_vault(buffer), self.remote);
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;
        Ok(())
    }

    /// Update a vault.
    async fn update_vault(&self, id: &VaultId, buffer: &[u8]) -> Result<()> {
        let (status, _) =
            retry!(|| self.remote.update_vault(id, buffer), self.remote);
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;
        Ok(())
    }

    /// Import a vault into an account that already exists on the remote.
    async fn delete_vault(&self, id: &VaultId) -> Result<()> {
        let (status, _) =
            retry!(|| self.remote.delete_vault(id), self.remote);
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;
        Ok(())
    }

    async fn sync_pull_folder(
        &self,
        last_commit: Option<&CommitHash>,
        client_proof: &CommitProof,
        folder: &Summary,
    ) -> Result<bool> {
        let last_commit = last_commit.ok_or_else(|| Error::NoRootCommit)?;

        let (status, (num_events, body)) = retry!(
            || self.remote.diff(folder.id(), last_commit, client_proof),
            self.remote
        );
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        if num_events > 0 {
            let patch: Patch = decode(&body).await?;
            let events = patch.into_events().await?;
            let mut writer = self.local.write().await;
            writer.patch(folder, events).await?;
        }

        Ok(num_events > 0)
    }

    async fn sync_pull_account(
        &self,
        account_status: AccountStatus,
    ) -> Result<()> {
        for (folder_id, remote_proof) in account_status.proofs {
            let (last_commit, commit_proof, folder) = {
                let local = self.local.read().await;
                let folder = local
                    .state()
                    .find_vault(&(folder_id.clone().into()))
                    .cloned()
                    .ok_or(Error::CacheNotAvailable(folder_id))?;
                let event_log = local
                    .cache()
                    .get(&folder_id)
                    .ok_or(Error::CacheNotAvailable(folder_id))?;

                let last_commit = event_log.last_commit().await?;
                let commit_proof = event_log.tree().head()?;
                (last_commit, commit_proof, folder)
            };

            self.sync_pull_folder(
                last_commit.as_ref(),
                &commit_proof,
                &folder,
            )
            .await?;
        }

        Ok(())
    }

    /// Create an account on the remote.
    async fn sync_create_remote_account(&self) -> Result<()> {
        let folder_buffer = {
            let local = self.local.read().await;
            let default_folder = local
                .state()
                .find(|s| s.flags().is_default())
                .ok_or(Error::NoDefaultFolder)?
                .clone();

            let folder_path = local.vault_path(&default_folder);
            vfs::read(folder_path).await?
        };

        // Create the account and default folder on the remote
        self.create_account(folder_buffer).await?;

        // Import other folders into the remote
        let other_folders: Vec<Summary> = {
            let local = self.local.read().await;
            local
                .state()
                .summaries()
                .into_iter()
                .filter(|s| !s.flags().is_default())
                .map(|s| s.clone())
                .collect()
        };

        for folder in other_folders {
            let folder_buffer = {
                let local = self.local.read().await;
                let folder_path = local.vault_path(&folder);
                vfs::read(folder_path).await?
            };

            self.import_vault(&folder_buffer).await?;
        }

        // FIXME: import files here!

        Ok(())
    }

    async fn patch(
        &self,
        before_last_commit: Option<&CommitHash>,
        before_client_proof: &CommitProof,
        folder: &Summary,
        events: &[WriteEvent<'static>],
    ) -> Result<()> {
        let span = span!(Level::DEBUG, "patch remote");
        let _enter = span.enter();

        let patch = {
            let reader = self.local.read().await;
            let event_log = reader
                .cache()
                .get(folder.id())
                .ok_or(Error::CacheNotAvailable(*folder.id()))?;
            event_log.patch_until(before_last_commit).await?
        };

        tracing::debug!(num_patch_events = %patch.0.len());

        let (status, (server_proof, match_proof)) = retry!(
            || self.remote.apply_patch(
                folder.id(),
                before_client_proof,
                &patch,
            ),
            self.remote
        );

        tracing::debug!(patch_status = %status);

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        Ok(())
    }
}

#[async_trait]
impl RemoteSync for RemoteBridge {
    async fn sync(&self) -> Result<()> {
        // Ensure our folder state is the latest version on disc
        {
            let mut local = self.local.write().await;
            local.load_vaults().await?;
        }

        let account_status = self.account_status().await?;
        if !account_status.exists {
            self.sync_create_remote_account().await
        } else {
            self.sync_pull_account(account_status).await
        }
    }

    async fn sync_before_apply_change(
        &self,
        last_commit: Option<&CommitHash>,
        client_proof: &CommitProof,
        folder: &Summary,
    ) -> Result<bool> {
        self.sync_pull_folder(last_commit, client_proof, folder)
            .await
    }

    async fn sync_send_events(
        &self,
        before_last_commit: Option<&CommitHash>,
        before_client_proof: &CommitProof,
        folder: &Summary,
        events: &[WriteEvent<'static>],
    ) -> std::result::Result<(), SyncError> {
        let events = events.to_vec();
        let mut patch_events = Vec::new();
        let mut create_folders = Vec::new();
        let mut update_folders = Vec::new();
        let mut delete_folders = Vec::new();

        for event in events {
            match event {
                WriteEvent::CreateVault(buf) => create_folders.push(buf),
                WriteEvent::UpdateVault(buf) => update_folders.push((folder.id(), buf)),
                WriteEvent::DeleteVault => delete_folders.push(folder.id()),
                _ => patch_events.push(event),
            }
        }

        // New folders must go via the vaults service,
        // and must not be included in any patch events
        for buf in create_folders {
            self.import_vault(buf.as_ref())
                .await
                .map_err(SyncError::One)?;
        }

        for (id, buf) in update_folders {
            self.update_vault(id, buf.as_ref())
                .await
                .map_err(SyncError::One)?;
        }

        for id in delete_folders {
            self.delete_vault(id).await.map_err(SyncError::One)?;
        }

        if !patch_events.is_empty() {
            self.patch(
                before_last_commit,
                before_client_proof,
                folder,
                patch_events.as_slice(),
            )
            .await
            .map_err(SyncError::One)?;
        }

        Ok(())
    }

    async fn sync_receive_events(
        &self,
        events: &[WriteEvent<'static>],
    ) -> Result<()> {
        todo!();
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
