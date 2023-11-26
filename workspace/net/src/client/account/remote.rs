//! Bridge between a local provider and a remote server.
use crate::{
    client::{
        net::{MaybeRetry, RpcClient},
        sync::SyncData,
        Error, RemoteSync, Result, SyncError, SyncOptions,
    },
    retry,
};

use async_trait::async_trait;
use http::StatusCode;

use sos_sdk::{
    account::{AccountStatus, LocalProvider},
    commit::{CommitHash, CommitProof, CommitState, Comparison},
    crypto::SecureAccessKey,
    decode,
    events::{Event, Patch, WriteEvent},
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
            || self.remote.create_folder(buffer, secure_key.cloned()),
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
            retry!(|| self.remote.update_folder(id, buffer), self.remote);

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
            writer.patch(folder, events).await?;
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
            let patch = event_log.patch_until(Some(from_commit)).await?;
            let proof = event_log.tree().proof_at(from_commit)?;
            (patch, proof)
        };

        let num_events = patch.0.len();

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

    async fn sync_folder(
        &self,
        folder: &Summary,
        last_commit: &CommitHash,
        commit_proof: &CommitProof,
        remote: Option<CommitState>,
    ) -> Result<bool> {
        let remote = if let Some(remote) = remote {
            remote
        } else {
            let (remote, _) = self
                .folder_status(folder.id(), Some(commit_proof.clone()))
                .await?;
            remote
        };

        let (remote_commit, remote_proof) = remote;
        let comparison = {
            let local = self.local.read().await;
            let folder = local
                .state()
                .find_vault(&(folder.id().clone().into()))
                .cloned()
                .ok_or(Error::CacheNotAvailable(*folder.id()))?;
            let event_log = local
                .cache()
                .get(folder.id())
                .ok_or(Error::CacheNotAvailable(*folder.id()))?;
            event_log.tree().compare(&remote_proof)?
        };

        let equal = matches!(&comparison, Comparison::Equal);
        let contains = matches!(&comparison, Comparison::Contains(_, _));
        let ahead = contains && commit_proof.len() > remote_proof.len();

        if ahead {
            self.push_folder(&folder, &remote_commit, &remote_proof)
                .await
        } else if !equal {
            self.pull_folder(&folder, last_commit, commit_proof).await
        } else {
            Ok(false)
        }
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
                    .state()
                    .find_vault(&(folder_id.clone().into()))
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
                &last_commit,
                &commit_proof,
                Some(remote),
            )
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
        commit_state: &CommitState,
        folder: &Summary,
        _events: &[WriteEvent],
    ) -> Result<()> {
        let span = span!(Level::DEBUG, "patch");
        let _enter = span.enter();

        let (last_commit, commit_proof) = commit_state;

        let patch = {
            let reader = self.local.read().await;
            let event_log = reader
                .cache()
                .get(folder.id())
                .ok_or(Error::CacheNotAvailable(*folder.id()))?;
            event_log.patch_until(Some(last_commit)).await?
        };

        tracing::debug!(num_patch_events = %patch.0.len());

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
            || options.origins.contains(&self.origin);

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

    async fn sync_before_apply_change(
        &self,
        folder: &Summary,
        last_commit: &CommitHash,
        client_proof: &CommitProof,
    ) -> Result<bool> {
        self.sync_folder(folder, last_commit, client_proof, None)
            .await
    }

    async fn sync_send_events(
        &self,
        folder: &Summary,
        commit_state: &CommitState,
        events: &[Event],
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
                Event::Write(_, event) => match event {
                    WriteEvent::CreateVault(buf) => {
                        if let Some(SyncData::CreateVault(secure_key)) = item
                        {
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
                    WriteEvent::DeleteVault => {
                        delete_folders.push(folder.id())
                    }
                    _ => patch_events.push(event),
                },
                _ => {}
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

#[cfg(not(target_arch = "wasm32"))]
mod listen {
    use crate::client::{
        Error, ListenOptions, RemoteBridge, Result, WebSocketHandle,
    };
    use sos_sdk::prelude::{
        AccessKey, ChangeAction, ChangeEvent, ChangeNotification,
        SecureAccessKey, Summary, VaultId, VaultRef,
    };

    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};
    use tracing::{span, Level};

    /// Channels we use to communicate with the
    /// user account storage.
    pub(crate) struct UserStorageReceiver {
        /// Receive a secure access key from the remote listener.
        pub secure_access_key_rx: mpsc::Receiver<(VaultId, SecureAccessKey)>,

        /// Receive a message when a vault is removed.
        pub remove_vault_rx: mpsc::Receiver<VaultId>,
    }

    /// Channels used to get a reply from the account storage.
    pub(crate) struct UserStorageSender {
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
            remote_bridge_tx: Arc<RemoteBridgeSender>,
            remote_bridge_rx: Arc<Mutex<RemoteBridgeReceiver>>,
        ) -> Result<()> {
            let local = bridge.local();
            tracing::debug!(
                folder = %folder.id(),
                "pull new folder");

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
                                .state()
                                .find(|s| s.id() == &id)
                                .cloned()
                                .ok_or(Error::CacheNotAvailable(id))?;
                            writer.remove_vault(&summary).await?;
                        }

                        // Notify the account storage of the folder
                        // removal so it can clean up the delegated
                        // passphrase from the identity vault
                        remote_bridge_tx
                            .remove_vault_tx
                            .send(*summary.id())
                            .await?;
                    }
                    (ChangeAction::Create(folder, secure_key), None) => {
                        Self::create_or_update_folder(
                            Arc::clone(&bridge),
                            folder,
                            folder_exists,
                            secure_key,
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
        ) -> (WebSocketHandle, UserStorageReceiver, UserStorageSender)
        {
            let remote_bridge = Arc::clone(&bridge);

            let (secure_access_key_tx, secure_access_key_rx) =
                mpsc::channel::<(VaultId, SecureAccessKey)>(16);

            let (remove_vault_tx, remove_vault_rx) =
                mpsc::channel::<VaultId>(16);

            let (access_key_tx, access_key_rx) =
                mpsc::channel::<AccessKey>(16);

            let user_storage_rx = UserStorageReceiver {
                secure_access_key_rx,
                remove_vault_rx,
            };

            let user_storage_tx = UserStorageSender { access_key_tx };

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

pub(crate) use listen::{UserStorageReceiver, UserStorageSender};
