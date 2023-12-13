//! Bridge between local storage and a remote server.
use crate::client::{
    net::RpcClient, Error, RemoteSync, Result, SyncError, SyncOptions,
};

use async_trait::async_trait;
use http::StatusCode;
use serde::{Deserialize, Serialize};

use sos_sdk::{
    commit::{CommitHash, CommitProof, CommitState, Comparison},
    decode,
    events::{AccountEvent, Event, LogEvent, WriteEvent},
    signer::{ecdsa::BoxedEcdsaSigner, ed25519::BoxedEd25519Signer},
    storage::Storage,
    sync::{
        AccountDiff, Client, FolderDiff, FolderPatch, Patch, SyncComparison,
        SyncDiff, SyncStatus,
    },
    url::Url,
    vault::Summary,
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

impl fmt::Display for HostedOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.url)
    }
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
            Self::Hosted(host) => host.fmt(f),
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
    local: Arc<RwLock<Storage>>,
    /// Client to use for remote communication.
    remote: RpcClient,
}

impl RemoteBridge {
    /// Create a new remote bridge that wraps the given
    /// local provider.
    pub fn new(
        local: Arc<RwLock<Storage>>,
        origin: HostedOrigin,
        signer: BoxedEcdsaSigner,
        device: BoxedEd25519Signer,
        keypair: Keypair,
    ) -> Result<Self> {
        let remote = RpcClient::new(origin.clone(), signer, device, keypair)?;
        Ok(Self {
            origin,
            local,
            remote,
        })
    }

    /// Clone of the local provider.
    pub fn local(&self) -> Arc<RwLock<Storage>> {
        Arc::clone(&self.local)
    }

    /// Client implementation.
    pub fn client(&self) -> &RpcClient {
        &self.remote
    }
}

/// Sync helper functions.
impl RemoteBridge {
    /// Perform the noise protocol handshake.
    pub async fn handshake(&self) -> Result<()> {
        Ok(self.remote.handshake().await?)
    }

    /*
    async fn push_identity(
        &self,
        commit_state: &CommitState,
    ) -> Result<()> {
        let patch: FolderPatch = {
            let local = self.local.read().await;
            let log = local.identity_log();
            let reader = log.read().await;
            reader.diff(Some(&commit_state.0)).await?
        };

        if !patch.is_empty() {
            self.remote.patch_identity(&commit_state.1, &patch).await?;
        }

        Ok(())
    }
    */
    
    /*
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

        let (num_events, body) = self
            .remote
            .diff_folder(folder.id(), last_commit, client_proof)
            .await?;

        tracing::debug!(num_events = ?num_events);

        if num_events > 0 {
            let patch: Patch<WriteEvent> = decode(&body).await?;
            let mut writer = self.local.write().await;
            writer.patch(folder, (&patch).into()).await?;
        }

        Ok(num_events > 0)
    }
    */
    
    /*
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
            let patch: Patch<WriteEvent> =
                event_log.diff(Some(from_commit)).await?;
            let proof = event_log.tree().proof_at(from_commit)?;
            (patch, proof)
        };

        let num_events = patch.len();

        tracing::debug!(
            num_events = %num_events,
            proof = ?proof,
        );

        self.remote
            .patch_folder(folder.id(), &proof, &patch)
            .await?;

        Ok(num_events > 0)
    }
    */
    
    /*
    #[deprecated(note = "use pull_account2() instead")]
    async fn pull_account(&self, sync_status: &SyncStatus) -> Result<()> {
        for (folder_id, (remote_commit, remote_proof)) in &sync_status.folders
        {
            let (folder, last_commit, commit_proof) = {
                let local = self.local.read().await;
                let folder = local
                    .find_folder(&(folder_id.clone().into()))
                    .cloned()
                    .ok_or(Error::CacheNotAvailable(*folder_id))?;
                let event_log = local
                    .cache()
                    .get(&folder_id)
                    .ok_or(Error::CacheNotAvailable(*folder_id))?;

                let last_commit = event_log
                    .tree()
                    .last_commit()
                    .ok_or(Error::NoRootCommit)?;
                let commit_proof = event_log.tree().head()?;
                (folder, last_commit, commit_proof)
            };

            let remote = (remote_commit.clone(), remote_proof.clone());
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
    */

    /*
    async fn pull_account2(
        &self,
        local_status: &SyncStatus,
        options: &SyncOptions,
    ) -> Result<SyncStatus> {
        let diff = self.remote.pull(local_status).await?;

        if let Some(diff) = &diff.identity {
            let storage = self.local.read().await;
            let identity = storage.identity_log();
            let mut writer = identity.write().await;
            writer.patch_checked(&diff.before, &diff.patch).await?;

            // FIXME: assert on after commit proofs
        }

        if let Some(diff) = &diff.account {
            let storage = self.local.read().await;
            let account = storage.account_log();
            let mut writer = account.write().await;
            writer.patch_checked(&diff.before, &diff.patch).await?;
        }

        for (id, diff) in &diff.folders {
            let mut storage = self.local.write().await;
            let mut event_log = storage
                .cache_mut()
                .get_mut(id)
                .ok_or(Error::CacheNotAvailable(*id))?;
            event_log.patch_checked(&diff.before, &diff.patch).await?;

            // FIXME: assert on after commit proofs
        }

        let storage = self.local.read().await;
        let sync_status = storage.sync_status().await?;

        Ok(sync_status)
    }
    */
    
    /*
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

        let patch: Patch<WriteEvent> = {
            let reader = self.local.read().await;
            let event_log = reader
                .cache()
                .get(folder.id())
                .ok_or(Error::CacheNotAvailable(*folder.id()))?;
            event_log.diff(Some(last_commit)).await?
        };

        tracing::debug!(num_patch_events = %patch.len());

        self.remote
            .patch_folder(folder.id(), commit_proof, &patch)
            .await?;

        Ok(())
    }
    */

    async fn sync_account(&self, remote_status: SyncStatus) -> Result<()> {
        let comparison = {
            let storage = self.local.read().await;
            // Compare local status to the remote
            SyncComparison::new(&*storage, remote_status).await?
        };

        // Only make network requests when the status differ
        if comparison.needs_sync() {
            let mut storage = self.local.write().await;
            let push = comparison.diff(&*storage).await?;
            let pull =
                self.remote.sync(&comparison.local_status, &push).await?;
            
            storage.apply_diff(&pull, Default::default()).await?;

            // TODO: apply event data from remote!
        }

        Ok(())
    }

    async fn execute_sync(&self) -> Vec<Error> {
        let mut errors = Vec::new();
        match self.remote.sync_status().await {
            Ok(sync_status) => {
                if let Some(sync_status) = sync_status {
                    if let Err(e) = self.sync_account(sync_status).await {
                        errors.push(e);
                    }
                } else {
                    if let Err(e) = self.create_remote_account().await {
                        errors.push(e);
                    }
                }
            }
            Err(e) => {
                errors.push(e);
            }
        }
        errors
    }

    /// Create an account on the remote.
    async fn create_remote_account(&self) -> Result<()> {
        let local = self.local.read().await;
        let public_account = local.change_set().await?;
        self.remote.create_account(&public_account).await?;

        // FIXME: import files here!

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
        let span = span!(Level::DEBUG, "sync");
        let _enter = span.enter();

        let should_sync = options.origins.is_empty()
            || options
                .origins
                .iter()
                .find(|&o| o == &Origin::Hosted(self.origin.clone()))
                .is_some();

        if !should_sync {
            tracing::warn!(origin = %self.origin, "skip sync");
            return None;
        }

        tracing::debug!(origin = %self.origin.url);

        let errors = self.execute_sync().await;
        if errors.is_empty() {
            None
        } else {
            let mut errors = errors
                .into_iter()
                .map(|e| {
                    let origin: Origin = self.origin.clone().into();
                    (origin, e)
                })
                .collect::<Vec<_>>();
            Some(SyncError::Multiple(errors))
        }
    }

    /*
    async fn pull(
        &self,
        local_status: &SyncStatus,
        options: &SyncOptions,
    ) -> std::result::Result<SyncStatus, SyncError> {
        self.pull_account2(local_status, options)
            .await
            .map_err(|e| SyncError::One(e))
    }
    */
    
    /*
    async fn sync_folder(
        &self,
        folder: &Summary,
        commit_state: &CommitState,
        remote: Option<CommitState>,
        _options: &SyncOptions,
    ) -> std::result::Result<bool, SyncError> {
        let (last_commit, commit_proof) = commit_state;

        let remote = if let Some(remote) = remote {
            remote
        } else {
            let (remote, _) = self
                .remote
                .folder_status(folder.id(), Some(&commit_proof))
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
    */

    /*
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
                    AccountEvent::CreateFolder(_),
                    WriteEvent::CreateVault(buf),
                ) => {
                    create_folders.push(buf);
                }
                Event::Folder(
                    AccountEvent::UpdateFolder(id),
                    WriteEvent::CreateVault(buf),
                ) => {
                    update_folders.push((id, buf));
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
        for buf in create_folders {
            self.remote
                .create_folder(buf.as_ref())
                .await
                .map_err(SyncError::One)?;
        }

        for (id, buf) in update_folders {
            self.remote
                .update_folder(&id, buf)
                .await
                .map_err(SyncError::One)?;
        }

        for id in delete_folders {
            self.remote
                .delete_folder(&id)
                .await
                .map_err(SyncError::One)?;
        }

        if !patch_events.is_empty() {
            self.patch(commit_state, folder, patch_events.as_slice())
                .await
                .map_err(SyncError::One)?;
        }

        Ok(())
    }
    */

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
            sync::RemoteSync,
        },
        events::{ChangeAction, ChangeEvent, ChangeNotification},
    };
    use sos_sdk::prelude::{
        AccountEvent, Event, FolderRef, VaultId, WriteEvent,
    };

    use std::sync::Arc;
    use tracing::{span, Level};

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
                    ChangeEvent::CreateFolder(event) => {
                        ChangeAction::CreateFolder(event.clone())
                    }
                    ChangeEvent::UpdateFolder(event) => {
                        ChangeAction::UpdateFolder(event.clone())
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

        async fn import_folder(
            bridge: Arc<RemoteBridge>,
            folder_id: VaultId,
            buffer: impl AsRef<[u8]>,
        ) -> Result<()> {
            let local = bridge.local();
            tracing::debug!(
                folder = %folder_id,
                "import_folder");

            let mut writer = local.write().await;
            writer.import_folder(buffer, None).await?;

            Ok(())
        }

        async fn on_change_notification(
            bridge: Arc<RemoteBridge>,
            change: ChangeNotification,
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
                            change_root = ?change.proof().root(),
                            root = ?head.root());

                        // Looks like the change was made elsewhere
                        // and we should attempt to sync with the server
                        if change.proof().root() != head.root() {
                            tracing::debug!(
                                folder = %summary.id(),
                                "proofs differ, trying sync");

                            if let Some(e) = bridge.sync().await {
                                tracing::error!(
                                    error = ?e,
                                    "bridge listen change sync failed",
                                );
                            }
                        } else {
                            tracing::debug!(
                                folder = %summary.id(),
                                "proofs match, up to date");
                        }
                    }
                    (ChangeAction::Remove(_), Some(summary)) => {
                        let mut writer = local.write().await;
                        writer.delete_folder(&summary).await?;
                    }
                    (ChangeAction::CreateFolder(event), None) => {
                        if let Event::Folder(
                            AccountEvent::CreateFolder(id, _),
                            WriteEvent::CreateVault(buf),
                        ) = event
                        {
                            Self::import_folder(Arc::clone(&bridge), id, buf)
                                .await?;
                        }
                    }
                    (ChangeAction::UpdateFolder(event), Some(_)) => {
                        if let Event::Folder(
                            AccountEvent::UpdateFolder(id),
                            WriteEvent::CreateVault(buf),
                        ) = event
                        {
                            Self::import_folder(Arc::clone(&bridge), id, buf)
                                .await?;
                        }
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
        ) -> WebSocketHandle {
            let remote_bridge = Arc::clone(&bridge);

            let handle = bridge.remote.listen(options, move |notification| {
                let bridge = Arc::clone(&remote_bridge);
                async move {
                    let span = span!(Level::DEBUG, "on_change_event");
                    let _enter = span.enter();
                    tracing::debug!(notification = ?notification);
                    if let Err(e) =
                        Self::on_change_notification(bridge, notification)
                            .await
                    {
                        tracing::error!(error = ?e);
                    }
                }
            });

            handle
        }
    }
}
