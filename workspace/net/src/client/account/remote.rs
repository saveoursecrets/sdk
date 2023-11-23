//! Bridge between a local provider and a remote server.
use crate::{
    client::{
        net::{MaybeRetry, RpcClient},
        sync::SyncData,
        Error, ListenOptions, LocalProvider, RemoteSync, Result, SyncError,
        WebSocketHandle,
    },
    retry,
};

use async_trait::async_trait;
use http::StatusCode;

use sos_sdk::{
    account::AccountStatus,
    commit::{CommitHash, CommitProof},
    crypto::SecureAccessKey,
    decode,
    events::{Patch, WriteEvent},
    mpc::Keypair,
    signer::ecdsa::BoxedEcdsaSigner,
    url::Url,
    vault::{Summary, VaultId},
    vfs,
};

use std::{any::Any, collections::HashMap, fmt, sync::Arc};
use tokio::sync::RwLock;

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

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.url)
    }
}

/// Remote synchronization target.
pub type Remote = Box<dyn RemoteSync>;

/// Collection of remote targets for synchronization.
pub type Remotes = HashMap<Origin, Remote>;

/// Bridge between a local provider and a remote.
#[derive(Clone)]
pub struct RemoteBridge {
    /// Origin for this remote.
    origin: Origin,
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
        let remote = RpcClient::new(origin.clone(), signer, keypair)?;
        Ok(Self {
            origin,
            local,
            remote,
        })
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
        let span = span!(Level::DEBUG, "create_account");
        let _enter = span.enter();

        let (status, _) = retry!(
            || self.remote.create_account(buffer.clone()),
            self.remote
        );

        tracing::debug!(status = %status);

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;
        Ok(())
    }

    /// Load all events from a remote event log.
    async fn load_events(
        &self,
        id: &VaultId,
    ) -> Result<(CommitProof, Vec<u8>)> {
        let span = span!(Level::DEBUG, "load_events");
        let _enter = span.enter();

        let (status, (proof, buffer)) =
            retry!(|| self.remote.load_events(id), self.remote);

        tracing::debug!(status = %status);

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        Ok((proof, buffer.ok_or(Error::NoEventBuffer)?))
    }

    /// Create a folder on the remote.
    async fn create_folder(
        &self,
        buffer: &[u8],
        secure_key: Option<&SecureAccessKey>,
    ) -> Result<()> {
        let span = span!(Level::DEBUG, "import_folder");
        let _enter = span.enter();

        let (status, _) = retry!(
            || self.remote.create_vault(buffer, secure_key.cloned()),
            self.remote
        );

        tracing::debug!(status = %status);

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;
        Ok(())
    }

    /// Update a folder on the remote.
    async fn update_folder(&self, id: &VaultId, buffer: &[u8]) -> Result<()> {
        let span = span!(Level::DEBUG, "update_folder");
        let _enter = span.enter();

        let (status, _) =
            retry!(|| self.remote.update_vault(id, buffer), self.remote);

        tracing::debug!(status = %status);

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;
        Ok(())
    }

    /// Import a folder into an account that already exists on the remote.
    async fn delete_folder(&self, id: &VaultId) -> Result<()> {
        let span = span!(Level::DEBUG, "delete_folder");
        let _enter = span.enter();

        let (status, _) =
            retry!(|| self.remote.delete_vault(id), self.remote);

        tracing::debug!(status = %status);

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;
        Ok(())
    }

    async fn pull_folder(
        &self,
        last_commit: Option<&CommitHash>,
        client_proof: &CommitProof,
        folder: &Summary,
    ) -> Result<bool> {
        let span = span!(Level::DEBUG, "pull_folder");
        let _enter = span.enter();

        tracing::debug!(
            id = %folder.id(),
            last_commit = ?last_commit,
            client_proof = ?client_proof);

        let last_commit = last_commit.ok_or_else(|| Error::NoRootCommit)?;

        let (status, (num_events, body)) = retry!(
            || self.remote.diff(folder.id(), last_commit, client_proof),
            self.remote
        );

        tracing::debug!(status = %status);

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        tracing::debug!(num_events = ?num_events);

        if num_events > 0 {
            let patch: Patch = decode(&body).await?;
            let events = patch.into_events().await?;
            let mut writer = self.local.write().await;
            writer.patch(folder, events).await?;
        }

        Ok(num_events > 0)
    }

    async fn pull_account(
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

            self.pull_folder(last_commit.as_ref(), &commit_proof, &folder)
                .await?;
        }

        Ok(())
    }

    /// Create an account on the remote.
    async fn prepare_account(&self) -> Result<()> {
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

            self.create_folder(&folder_buffer, None).await?;
        }

        // FIXME: import files here!

        Ok(())
    }

    /// Send a local patch of events to the remote.
    async fn patch(
        &self,
        before_last_commit: Option<&CommitHash>,
        before_client_proof: &CommitProof,
        folder: &Summary,
        events: &[WriteEvent<'static>],
    ) -> Result<()> {
        let span = span!(Level::DEBUG, "patch");
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
            self.prepare_account().await
        } else {
            self.pull_account(account_status).await
        }
    }

    async fn sync_before_apply_change(
        &self,
        last_commit: Option<&CommitHash>,
        client_proof: &CommitProof,
        folder: &Summary,
    ) -> Result<bool> {
        self.pull_folder(last_commit, client_proof, folder).await
    }

    async fn sync_send_events(
        &self,
        before_last_commit: Option<&CommitHash>,
        before_client_proof: &CommitProof,
        folder: &Summary,
        events: &[WriteEvent<'static>],
        data: &[SyncData],
    ) -> std::result::Result<(), SyncError> {
        let events = events.to_vec();
        let mut patch_events = Vec::new();
        let mut create_folders = Vec::new();
        let mut update_folders = Vec::new();
        let mut delete_folders = Vec::new();

        for (index, event) in events.into_iter().enumerate() {
            let item = data.get(index);
            match event {
                WriteEvent::CreateVault(buf) => {
                    if let Some(SyncData::CreateVault(secure_key)) = item {
                        create_folders.push((buf, secure_key))
                    } else {
                        panic!(
                            "sync data is required for create vault event"
                        );
                    }
                }
                WriteEvent::UpdateVault(buf) => {
                    update_folders.push((folder.id(), buf))
                }
                WriteEvent::DeleteVault => delete_folders.push(folder.id()),
                _ => patch_events.push(event),
            }
        }

        // New folders must go via the vaults service,
        // and must not be included in any patch events
        for (buf, secure_key) in create_folders {
            self.create_folder(buf.as_ref(), Some(secure_key))
                .await
                .map_err(SyncError::One)?;
        }

        for (id, buf) in update_folders {
            self.update_folder(id, buf.as_ref())
                .await
                .map_err(SyncError::One)?;
        }

        for id in delete_folders {
            self.delete_folder(id).await.map_err(SyncError::One)?;
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

#[cfg(not(target_arch = "wasm32"))]
mod listen {
    use crate::client::{
        Error, ListenOptions, RemoteBridge, Result, WebSocketHandle,
    };
    use sos_sdk::prelude::{
        AccessKey, ChangeAction, ChangeEvent, ChangeNotification,
        CommitRelationship, SecureAccessKey, Summary, VaultId, VaultRef,
    };

    use futures::Future;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tracing::{span, Level};

    /// Channels we use to communicate with the
    /// user account storage.
    pub(crate) struct StorageChannels {
        /// Receive a secure access key from the remote listener.
        pub secure_access_key_rx: mpsc::Receiver<(VaultId, SecureAccessKey)>,
    }

    #[derive(Clone)]
    pub(crate) struct ListenChannels {
        /// Send a secure access key to the account storage for decryption.
        pub secure_access_key_tx: mpsc::Sender<(VaultId, SecureAccessKey)>,
    }

    // Listen and respond to change notifications
    #[cfg(not(target_arch = "wasm32"))]
    impl RemoteBridge {
        fn notification_actions(
            change: &ChangeNotification,
        ) -> Vec<ChangeAction> {
            // Gather actions corresponding to the events
            let mut actions = Vec::new();
            for event in change.changes() {
                let action = match event {
                    ChangeEvent::CreateVault(summary, secure_key) => {
                        ChangeAction::Create(
                            summary.clone(),
                            secure_key.clone(),
                        )
                    }
                    ChangeEvent::UpdateVault(summary) => {
                        ChangeAction::Update(summary.clone())
                    }
                    ChangeEvent::DeleteVault => {
                        ChangeAction::Remove(*change.vault_id())
                    }
                    _ => ChangeAction::Pull(*change.vault_id()),
                };
                actions.push(action);
            }
            actions
        }

        async fn create_or_update_folder(
            bridge: Arc<RemoteBridge>,
            folder: Summary,
            folder_exists: bool,
            secure_key: Option<SecureAccessKey>,
            listen_channels: Arc<ListenChannels>,
        ) -> Result<()> {
            let local = bridge.local();
            tracing::debug!(
                folder = %folder.id(),
                "pull new folder");

            let id = *folder.id();

            // Prepare the local provider for the new folder
            if !folder_exists {
                let mut writer = local.write().await;
                writer.add_local_cache(folder.clone()).await?;
            }

            // Load the event entire event log
            let (remote_proof, events_buffer) =
                bridge.load_events(&id).await?;
            {
                let mut writer = local.write().await;
                let mut event_log = writer
                    .cache_mut()
                    .get_mut(&id)
                    .ok_or(Error::CacheNotAvailable(id))?;

                // Write out the events we fetched
                event_log.write_buffer(&events_buffer).await?;

                // Check the proofs match afterwards
                let local_proof = event_log.tree().head()?;
                if local_proof != remote_proof {
                    return Err(Error::RootHashMismatch(
                        local_proof.into(),
                        remote_proof.into(),
                    ));
                }
            }

            let access_key: Option<AccessKey> =
                if let Some(secure_key) = secure_key {
                    // Send the secure access key to the
                    // account storage for decryption
                    listen_channels
                        .secure_access_key_tx
                        .send((*folder.id(), secure_key))
                        .await?;

                    // FIXME: wait to get the decrypted access key back
                    None
                } else {
                    None
                };

            // Updating an existing folder
            if folder_exists {
                let mut writer = local.write().await;
                writer.refresh_vault(&folder, access_key.as_ref()).await?;
            }

            // FIXME: create delegated passphrase
            // FIXME: for the folder here

            Ok(())
        }

        async fn on_change_notification(
            bridge: Arc<RemoteBridge>,
            change: ChangeNotification,
            listen_channels: Arc<ListenChannels>,
        ) -> Result<()> {
            let actions = Self::notification_actions(&change);
            let local = bridge.local();
            // Consume and react to the actions
            for action in actions {
                tracing::debug!(action = ?action, "action");

                let summary = {
                    let reader = local.read().await;
                    reader
                        .state()
                        .find_vault(&VaultRef::Id(*change.vault_id()))
                        .cloned()
                };

                let folder_exists = summary.is_some();

                match (action, summary) {
                    (ChangeAction::Pull(_), Some(summary)) => {
                        let head = {
                            let reader = local.read().await;
                            let tree = reader
                                .commit_tree(&summary)
                                .ok_or(sos_sdk::Error::NoRootCommit)?;
                            tree.head()?
                        };

                        tracing::debug!(
                            vault_id = ?summary.id(),
                            change_root = ?change.proof().root_hex(),
                            root = ?head.root_hex());

                        // Looks like the change was made elsewhere
                        // and we should attempt to sync with the server
                        if change.proof().root() != head.root() {
                            tracing::debug!(
                                folder = %summary.id(),
                                "proofs differ, trying pull");

                            let (last_commit, commit_proof) = {
                                let reader = local.read().await;
                                let event_log = reader
                                    .cache()
                                    .get(summary.id())
                                    .ok_or(Error::CacheNotAvailable(
                                        *summary.id(),
                                    ))?;
                                let last_commit =
                                    event_log.last_commit().await?;
                                let commit_proof = event_log.tree().head()?;
                                (last_commit, commit_proof)
                            };

                            tracing::debug!(
                                last_commit = ?last_commit,
                                commit_proof = ?commit_proof);

                            bridge
                                .pull_folder(
                                    last_commit.as_ref(),
                                    &commit_proof,
                                    &summary,
                                )
                                .await?;
                        } else {
                            tracing::debug!(
                                folder = %summary.id(),
                                "proofs match, up to date");
                        }
                    }
                    (ChangeAction::Remove(id), Some(summary)) => {
                        {
                            let mut writer = local.write().await;
                            let summary = writer
                                .state()
                                .find(|s| s.id() == &id)
                                .cloned()
                                .ok_or(Error::CacheNotAvailable(id))?;
                            writer.remove_local_cache(&summary)?;
                        }

                        // FIXME: remove delegated passphrase
                        // FIXME: for the folder here
                    }
                    (ChangeAction::Create(folder, secure_key), None) => {
                        Self::create_or_update_folder(
                            Arc::clone(&bridge),
                            folder,
                            folder_exists,
                            secure_key,
                            Arc::clone(&listen_channels),
                        )
                        .await?;
                    }
                    (ChangeAction::Update(folder), Some(_)) => {
                        Self::create_or_update_folder(
                            Arc::clone(&bridge),
                            folder,
                            folder_exists,
                            None,
                            Arc::clone(&listen_channels),
                        )
                        .await?;
                    }
                    _ => {}
                }
            }
            Ok(())
        }

        /// Spawn a task that listens for changes
        /// from the remote server and applies any changes
        /// from the remote to the local provider.
        ///
        /// The keypair for the websocket connection must not be
        /// the same as the main client so you should always generate
        /// a new keypair for this connection. Otherwise transports
        /// will collide on the server as they are identified by
        /// public key.
        pub(crate) fn listen(
            bridge: Arc<RemoteBridge>,
            options: ListenOptions,
        ) -> (WebSocketHandle, StorageChannels) {
            let remote_bridge = Arc::clone(&bridge);

            let (secure_access_key_tx, secure_access_key_rx) =
                mpsc::channel::<(VaultId, SecureAccessKey)>(16);

            let storage_channels = StorageChannels {
                secure_access_key_rx,
            };

            let listen_channels = Arc::new(ListenChannels {
                secure_access_key_tx,
            });

            let handle = bridge.remote.listen(options, move |notification| {
                let bridge = Arc::clone(&remote_bridge);
                let listener = Arc::clone(&listen_channels);
                async move {
                    let span = span!(Level::DEBUG, "on_change_event");
                    let _enter = span.enter();
                    tracing::debug!(notification = ?notification);
                    if let Err(e) = Self::on_change_notification(
                        bridge,
                        notification,
                        Arc::clone(&listener),
                    )
                    .await
                    {
                        tracing::error!(error = ?e);
                    }
                }
            });

            (handle, storage_channels)
        }
    }
}

pub(crate) use listen::StorageChannels;
