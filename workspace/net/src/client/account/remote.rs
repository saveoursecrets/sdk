//! Bridge between local storage and a remote server.
use crate::{
    client::{
        net::{MaybeRetry, RpcClient},
        Error, RemoteSync, Result, SyncError, SyncOptions,
    },
    events::Patch,
    retry,
};

use async_trait::async_trait;
use http::StatusCode;
use serde::{Deserialize, Serialize};

use sos_sdk::{
    account::SecureKeys,
    commit::{CommitHash, CommitProof, CommitState, Comparison},
    crypto::SecureAccessKey,
    decode,
    events::{AccountEvent, AccountReducer, Event, WriteEvent},
    signer::ecdsa::BoxedEcdsaSigner,
    storage::{AccountStatus, FolderStorage},
    url::Url,
    vault::{Summary, VaultId},
    vfs,
};

use mpc_protocol::Keypair;
use std::{any::Any, collections::HashMap, fmt, sync::Arc};
use tokio::sync::RwLock;

use tracing::{span, Level};

/// Self hosted origin.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostedOrigin {
    /// Name of the origin.
    pub name: String,
    /// URL of the remote server.
    pub url: Url,
    /// Public key of the remote server.
    #[serde(with = "hex::serde")]
    pub public_key: Vec<u8>,
}

/// Remote origin information.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Origin {
    /// Self hosted remote.
    Hosted(HostedOrigin),
}

impl Origin {
    /// The URL for this origin.
    pub fn url(&self) -> &Url {
        match self {
            Self::Hosted(origin) => &origin.url,
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hosted(host) => {
                write!(f, "{} ({})", host.name, host.url)
            }
        }
    }
}

impl From<&HostedOrigin> for Origin {
    fn from(value: &HostedOrigin) -> Self {
        value.clone().into()
    }
}

impl From<HostedOrigin> for Origin {
    fn from(value: HostedOrigin) -> Self {
        Origin::Hosted(value)
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
    origin: HostedOrigin,
    /// Local provider.
    local: Arc<RwLock<FolderStorage>>,
    /// Client to use for remote communication.
    remote: RpcClient,
}

impl RemoteBridge {
    /// Create a new remote bridge that wraps the given
    /// local provider.
    pub fn new(
        local: Arc<RwLock<FolderStorage>>,
        origin: HostedOrigin,
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
    pub fn local(&self) -> Arc<RwLock<FolderStorage>> {
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
    async fn create_account(
        &self,
        buffer: &[u8],
        secure_access_key: &SecureAccessKey,
    ) -> Result<()> {
        let span = span!(Level::DEBUG, "create_account");
        let _enter = span.enter();

        let (status, _) = retry!(
            || self.remote.create_account(buffer, secure_access_key),
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
        secure_key: &SecureAccessKey,
    ) -> Result<()> {
        let span = span!(Level::DEBUG, "import_folder");
        let _enter = span.enter();

        let (status, _) = retry!(
            || self.remote.create_folder(buffer, secure_key),
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
    async fn update_folder(
        &self,
        id: &VaultId,
        buffer: &[u8],
        secure_access_key: &SecureAccessKey,
    ) -> Result<()> {
        let span = span!(Level::DEBUG, "update_folder");
        let _enter = span.enter();

        let (status, _) = retry!(
            || self.remote.update_folder(id, buffer, secure_access_key),
            self.remote
        );

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
            retry!(|| self.remote.delete_folder(id), self.remote);

        tracing::debug!(status = %status);

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;
        Ok(())
    }

    async fn folder_status(
        &self,
        vault_id: &VaultId,
        proof: Option<CommitProof>,
    ) -> Result<(CommitState, Option<CommitProof>)> {
        let span = span!(Level::DEBUG, "folder_status");
        let _enter = span.enter();

        let (status, (last_commit, remote_proof, match_proof)) = retry!(
            || self.remote.folder_status(vault_id, proof.clone()),
            self.remote
        );

        tracing::debug!(status = %status);

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;
        Ok(((last_commit, remote_proof), match_proof))
    }

    async fn pull_folder(
        &self,
        folder: &Summary,
        last_commit: &CommitHash,
        client_proof: &CommitProof,
    ) -> Result<bool> {
        let span = span!(Level::DEBUG, "pull_folder");
        let _enter = span.enter();

        tracing::debug!(
            id = %folder.id(),
            last_commit = ?last_commit,
            client_proof = ?client_proof);

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
            writer.patch(folder, events.iter().collect()).await?;
        }

        Ok(num_events > 0)
    }

    async fn push_folder(
        &self,
        folder: &Summary,
        from_commit: &CommitHash,
        _remote_proof: &CommitProof,
    ) -> Result<bool> {
        let span = span!(Level::DEBUG, "push_folder");
        let _enter = span.enter();

        tracing::debug!(
            id = %folder.id(),
            from_commit = %from_commit);

        let (patch, proof) = {
            let reader = self.local.read().await;
            let event_log = reader
                .cache()
                .get(folder.id())
                .ok_or(Error::CacheNotAvailable(*folder.id()))?;
            let patch: Patch =
                event_log.patch_until(Some(from_commit)).await?.into();
            let proof = event_log.tree().proof_at(from_commit)?;
            (patch, proof)
        };

        let num_events = patch.len();

        tracing::debug!(
            num_events = %num_events,
            proof = ?proof,
        );

        let (status, (_server_proof, _match_proof)) = retry!(
            || self.remote.apply_patch(folder.id(), &proof, &patch,),
            self.remote
        );

        tracing::debug!(push_status = %status);

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        Ok(num_events > 0)
    }

    async fn pull_account(
        &self,
        account_status: AccountStatus,
    ) -> Result<()> {
        for (folder_id, (remote_commit, remote_proof)) in
            account_status.proofs
        {
            let (folder, last_commit, commit_proof) = {
                let local = self.local.read().await;
                let folder = local
                    .find_folder(&(folder_id.clone().into()))
                    .cloned()
                    .ok_or(Error::CacheNotAvailable(folder_id))?;
                let event_log = local
                    .cache()
                    .get(&folder_id)
                    .ok_or(Error::CacheNotAvailable(folder_id))?;

                let last_commit = event_log
                    .last_commit()
                    .await?
                    .ok_or(Error::NoRootCommit)?;
                let commit_proof = event_log.tree().head()?;
                (folder, last_commit, commit_proof)
            };

            let remote = (remote_commit, remote_proof);
            self.sync_folder(
                &folder,
                &(last_commit, commit_proof),
                Some(remote),
                &Default::default(),
            )
            .await?;
        }

        Ok(())
    }

    /// Create an account on the remote.
    async fn prepare_account(&self) -> Result<()> {
        let canonical_folders = {
            let local = self.local.read().await;
            let log = local.account_log();
            let mut event_log = log.write().await;
            let reducer = AccountReducer::new(&mut *event_log);
            let canonical_folders = reducer.reduce().await?;
            let mut folders = Vec::new();
            for (id, secure_access_key) in canonical_folders {
                if let Some(folder) = local.find(|s| s.id() == &id) {
                    let buffer = local.read_vault_file(&folder).await?;
                    folders.push((folder.clone(), buffer, secure_access_key));
                } else {
                    tracing::warn!(id = %id, "missing folder");
                }
            }
            folders
        };

        let mut other_folders = Vec::new();
        let mut default_folder: Option<(Summary, Vec<u8>, SecureAccessKey)> =
            None;
        for (folder, buffer, secure_access_key) in canonical_folders {
            if folder.flags().is_default() && default_folder.is_none() {
                default_folder = Some((folder, buffer, secure_access_key));
            } else {
                other_folders.push((folder, buffer, secure_access_key));
            }
        }

        // Choose a folder to send for the create account
        if default_folder.is_none() && !other_folders.is_empty() {
            default_folder = Some(other_folders.remove(0));
        }

        // Create the account and default folder on the remote
        if let Some((_, buffer, secure_access_key)) = default_folder.take() {
            self.create_account(&buffer, &secure_access_key).await?;
            for (_, buffer, secure_access_key) in other_folders {
                self.create_folder(&buffer, &secure_access_key).await?;
            }
        } else {
            tracing::warn!("no default folder for sync");
        }

        // FIXME: import files here!

        Ok(())
    }

    /// Send a local patch of events to the remote.
    async fn patch(
        &self,
        commit_state: &CommitState,
        folder: &Summary,
        _events: &[WriteEvent],
    ) -> Result<()> {
        let span = span!(Level::DEBUG, "patch");
        let _enter = span.enter();

        let (last_commit, commit_proof) = commit_state;

        let patch: Patch = {
            let reader = self.local.read().await;
            let event_log = reader
                .cache()
                .get(folder.id())
                .ok_or(Error::CacheNotAvailable(*folder.id()))?;
            event_log.patch_until(Some(last_commit)).await?.into()
        };

        tracing::debug!(num_patch_events = %patch.len());

        let (status, (_server_proof, _match_proof)) = retry!(
            || self.remote.apply_patch(folder.id(), commit_proof, &patch,),
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
    async fn sync(&self) -> Option<SyncError> {
        self.sync_with_options(&Default::default()).await
    }

    async fn sync_with_options(
        &self,
        options: &SyncOptions,
    ) -> Option<SyncError> {
        let should_sync = options.origins.is_empty()
            || options
                .origins
                .iter()
                .find(|&o| o == &Origin::Hosted(self.origin.clone()))
                .is_some();

        if !should_sync {
            return None;
        }

        let span = span!(Level::DEBUG, "sync");
        let _enter = span.enter();

        // Ensure our folder state is the latest version on disc
        {
            let mut local = self.local.write().await;
            if let Err(e) = local.load_vaults().await {
                return Some(SyncError::One(e.into()));
            }
        }

        tracing::debug!(origin = %self.origin.url);

        match self.account_status().await {
            Ok(account_status) => {
                if !account_status.exists {
                    if let Err(e) = self.prepare_account().await {
                        Some(SyncError::One(e))
                    } else {
                        None
                    }
                } else {
                    if let Err(e) = self.pull_account(account_status).await {
                        Some(SyncError::One(e))
                    } else {
                        None
                    }
                }
            }
            Err(e) => Some(SyncError::One(e)),
        }
    }

    async fn sync_folder(
        &self,
        folder: &Summary,
        commit_state: &CommitState,
        remote: Option<CommitState>,
        options: &SyncOptions,
    ) -> std::result::Result<bool, SyncError> {
        let (last_commit, commit_proof) = commit_state;

        let remote = if let Some(remote) = remote {
            remote
        } else {
            let (remote, _) = self
                .folder_status(folder.id(), Some(commit_proof.clone()))
                .await
                .map_err(SyncError::One)?;
            remote
        };

        let (remote_commit, remote_proof) = remote;
        let comparison = {
            let local = self.local.read().await;
            let folder = local
                .find_folder(&(folder.id().clone().into()))
                .cloned()
                .ok_or(Error::CacheNotAvailable(*folder.id()))
                .map_err(SyncError::One)?;
            let event_log = local
                .cache()
                .get(folder.id())
                .ok_or(Error::CacheNotAvailable(*folder.id()))
                .map_err(SyncError::One)?;
            event_log
                .tree()
                .compare(&remote_proof)
                .map_err(|e| SyncError::One(e.into()))?
        };

        let equal = matches!(&comparison, Comparison::Equal);
        let contains = matches!(&comparison, Comparison::Contains(_, _));
        let ahead = contains && commit_proof.len() > remote_proof.len();

        let local_changed = if ahead {
            self.push_folder(&folder, &remote_commit, &remote_proof)
                .await
                .map_err(SyncError::One)?;
            false
        } else if !equal {
            self.pull_folder(&folder, last_commit, commit_proof)
                .await
                .map_err(SyncError::One)?
        } else {
            false
        };

        Ok(local_changed)
    }

    async fn sync_send_events(
        &self,
        folder: &Summary,
        commit_state: &CommitState,
        events: &[Event],
    ) -> std::result::Result<(), SyncError> {
        let events = events.to_vec();
        let mut patch_events = Vec::new();
        let mut create_folders = Vec::new();
        let mut update_folders = Vec::new();
        let mut delete_folders = Vec::new();

        for event in events {
            match event {
                Event::Folder(
                    AccountEvent::CreateFolder(_, secure_access_key),
                    WriteEvent::CreateVault(buf),
                ) => {
                    create_folders.push((buf, secure_access_key));
                }
                Event::Folder(
                    AccountEvent::UpdateFolder(id, secure_access_key),
                    WriteEvent::CreateVault(buf),
                ) => {
                    update_folders.push((id, buf, secure_access_key));
                }
                Event::Account(AccountEvent::DeleteFolder(id)) => {
                    delete_folders.push(id)
                }
                Event::Write(_, event) => match event {
                    _ => patch_events.push(event),
                },
                _ => {}
            }
        }

        // New folders must go via the vaults service,
        // and must not be included in any patch events
        for (buf, secure_key) in create_folders {
            self.create_folder(buf.as_ref(), &secure_key)
                .await
                .map_err(SyncError::One)?;
        }

        for (id, buf, secure_key) in update_folders {
            self.update_folder(&id, buf.as_ref(), &secure_key)
                .await
                .map_err(SyncError::One)?;
        }

        for id in delete_folders {
            self.delete_folder(&id).await.map_err(SyncError::One)?;
        }

        if !patch_events.is_empty() {
            self.patch(commit_state, folder, patch_events.as_slice())
                .await
                .map_err(SyncError::One)?;
        }

        Ok(())
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }

    fn as_any_mut(&mut self) -> &mut (dyn Any + Send + Sync) {
        self
    }
}

#[cfg(feature = "listen")]
mod listen {
    use crate::{
        client::{
            Error, ListenOptions, RemoteBridge, Result, WebSocketHandle,
        },
        events::{ChangeAction, ChangeEvent, ChangeNotification},
    };
    use sos_sdk::prelude::{
        AccessKey, FolderRef, SecureAccessKey, Summary, VaultId,
    };

    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};
    use tracing::{span, Level};

    /// Channels we use to communicate with the
    /// user account storage.
    pub(crate) struct NetworkAccountReceiver {
        /// Receive a secure access key from the remote listener.
        pub secure_access_key_rx: mpsc::Receiver<(VaultId, SecureAccessKey)>,

        /// Receive a message when a vault is removed.
        pub remove_vault_rx: mpsc::Receiver<VaultId>,
    }

    /// Channels used to get a reply from the account storage.
    pub(crate) struct NetworkAccountSender {
        /// Sends the decrypted access key from the
        /// storage to the remote bridge.
        pub access_key_tx: mpsc::Sender<AccessKey>,
    }

    /// Messages sent from the remote bridge.
    #[derive(Clone)]
    pub(crate) struct RemoteBridgeSender {
        /// Send a secure access key to the account storage for decryption.
        pub secure_access_key_tx: mpsc::Sender<(VaultId, SecureAccessKey)>,

        /// Send a message when a vault is removed.
        pub remove_vault_tx: mpsc::Sender<VaultId>,
    }

    /// Messages sent from the remote bridge.
    pub(crate) struct RemoteBridgeReceiver {
        /// Receive the decrypted access key from the account storage.
        pub access_key_rx: mpsc::Receiver<AccessKey>,
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
                    ChangeEvent::CreateVault(summary) => {
                        ChangeAction::Create(summary.clone())
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
            remote_bridge_tx: Arc<RemoteBridgeSender>,
            remote_bridge_rx: Arc<Mutex<RemoteBridgeReceiver>>,
        ) -> Result<()> {
            let local = bridge.local();
            tracing::debug!(
                folder = %folder.id(),
                "create_or_update_folder");

            let id = *folder.id();

            // Prepare the local provider for the new folder
            if !folder_exists {
                let mut writer = local.write().await;
                writer.prepare_vault(folder.clone()).await?;
            }

            // Load the event entire event log
            let (remote_proof, events_buffer) =
                bridge.load_events(&id).await?;
            {
                let mut writer = local.write().await;
                let event_log = writer
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
                    remote_bridge_tx
                        .secure_access_key_tx
                        .send((*folder.id(), secure_key))
                        .await?;

                    // Get the decrypted access key back
                    // so we can use it when refreshing the
                    // in-memory vault
                    let mut receiver = remote_bridge_rx.lock().await;
                    receiver.access_key_rx.recv().await
                } else {
                    None
                };

            // Updating an existing folder
            {
                let mut writer = local.write().await;
                writer.refresh_vault(&folder, access_key.as_ref()).await?;
            }

            Ok(())
        }

        async fn on_change_notification(
            bridge: Arc<RemoteBridge>,
            change: ChangeNotification,
            remote_bridge_tx: Arc<RemoteBridgeSender>,
            remote_bridge_rx: Arc<Mutex<RemoteBridgeReceiver>>,
        ) -> Result<()> {
            tracing::debug!("on_change_notification");
            let actions = Self::notification_actions(&change);
            let local = bridge.local();
            // Consume and react to the actions
            for action in actions {
                tracing::debug!(action = ?action, "action");

                let summary = {
                    let reader = local.read().await;
                    reader
                        .find_folder(&FolderRef::Id(*change.vault_id()))
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
                                let last_commit = event_log
                                    .last_commit()
                                    .await?
                                    .ok_or(Error::NoRootCommit)?;
                                let commit_proof = event_log.tree().head()?;
                                (last_commit, commit_proof)
                            };

                            tracing::debug!(
                                last_commit = ?last_commit,
                                commit_proof = ?commit_proof);

                            bridge
                                .pull_folder(
                                    &summary,
                                    &last_commit,
                                    &commit_proof,
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
                                .find(|s| s.id() == &id)
                                .cloned()
                                .ok_or(Error::CacheNotAvailable(id))?;
                            writer.delete_folder(&summary).await?;
                        }

                        // Notify the account storage of the folder
                        // removal so it can clean up the delegated
                        // passphrase from the identity vault
                        remote_bridge_tx
                            .remove_vault_tx
                            .send(*summary.id())
                            .await?;
                    }
                    (ChangeAction::Create(folder), None) => {
                        Self::create_or_update_folder(
                            Arc::clone(&bridge),
                            folder,
                            folder_exists,
                            None,
                            Arc::clone(&remote_bridge_tx),
                            Arc::clone(&remote_bridge_rx),
                        )
                        .await?;
                    }
                    (ChangeAction::Update(folder), Some(_)) => {
                        Self::create_or_update_folder(
                            Arc::clone(&bridge),
                            folder,
                            folder_exists,
                            None,
                            Arc::clone(&remote_bridge_tx),
                            Arc::clone(&remote_bridge_rx),
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
        ) -> (
            WebSocketHandle,
            NetworkAccountReceiver,
            NetworkAccountSender,
        ) {
            let remote_bridge = Arc::clone(&bridge);

            let (secure_access_key_tx, secure_access_key_rx) =
                mpsc::channel::<(VaultId, SecureAccessKey)>(16);

            let (remove_vault_tx, remove_vault_rx) =
                mpsc::channel::<VaultId>(16);

            let (access_key_tx, access_key_rx) =
                mpsc::channel::<AccessKey>(16);

            let user_storage_rx = NetworkAccountReceiver {
                secure_access_key_rx,
                remove_vault_rx,
            };

            let user_storage_tx = NetworkAccountSender { access_key_tx };

            let remote_bridge_tx = Arc::new(RemoteBridgeSender {
                secure_access_key_tx,
                remove_vault_tx,
            });

            let remote_bridge_rx =
                Arc::new(Mutex::new(RemoteBridgeReceiver { access_key_rx }));

            let handle = bridge.remote.listen(options, move |notification| {
                let bridge = Arc::clone(&remote_bridge);
                let tx = Arc::clone(&remote_bridge_tx);
                let rx = Arc::clone(&remote_bridge_rx);
                async move {
                    let span = span!(Level::DEBUG, "on_change_event");
                    let _enter = span.enter();
                    tracing::debug!(notification = ?notification);
                    if let Err(e) = Self::on_change_notification(
                        bridge,
                        notification,
                        Arc::clone(&tx),
                        Arc::clone(&rx),
                    )
                    .await
                    {
                        tracing::error!(error = ?e);
                    }
                }
            });

            (handle, user_storage_rx, user_storage_tx)
        }
    }
}

#[cfg(feature = "listen")]
pub(crate) use listen::{NetworkAccountReceiver, NetworkAccountSender};
