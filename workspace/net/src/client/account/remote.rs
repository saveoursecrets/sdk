//! Bridge between local storage and a remote server.
use crate::client::{
    net::RpcClient, Error, RemoteSync, Result, SyncError, SyncOptions,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use sos_sdk::{
    account::LocalAccount,
    signer::{ecdsa::BoxedEcdsaSigner, ed25519::BoxedEd25519Signer},
    storage::ClientStorage,
    sync::{self, Client, SyncComparison, SyncStatus},
    url::Url,
};

use mpc_protocol::Keypair;
use std::{any::Any, collections::HashMap, fmt, sync::Arc};
use tokio::sync::{Mutex, RwLock};

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

/// Bridge between a local account and a remote.
#[derive(Clone)]
pub struct RemoteBridge {
    /// Origin for this remote.
    origin: HostedOrigin,
    /// Account so we can replay events
    /// when a remote diff is merged.
    account: Arc<Mutex<LocalAccount>>,
    /// Client to use for remote communication.
    remote: RpcClient,
}

impl RemoteBridge {
    /// Create a new remote bridge that wraps the given
    /// local provider.
    pub fn new(
        account: Arc<Mutex<LocalAccount>>,
        origin: HostedOrigin,
        signer: BoxedEcdsaSigner,
        device: BoxedEd25519Signer,
        keypair: Keypair,
        connection_id: String,
    ) -> Result<Self> {
        let remote = RpcClient::new(
            origin.clone(),
            signer,
            device,
            keypair,
            connection_id,
        )?;
        Ok(Self {
            account,
            origin,
            remote,
        })
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

    /// Create an account on the remote.
    async fn create_remote_account(&self) -> Result<()> {
        let account = self.account.lock().await;
        let storage = account.storage()?;
        let storage = storage.read().await;
        let public_account = storage.change_set().await?;
        self.remote.create_account(&public_account).await?;

        // FIXME: import files here!

        Ok(())
    }

    async fn sync_account(&self, remote_status: SyncStatus) -> Result<()> {
        let mut account = self.account.lock().await;

        let (needs_sync, local_status, local_changes) =
            sync::diff(&*account, remote_status).await?;

        if needs_sync {
            let remote_changes =
                self.remote.sync(&local_status, &local_changes).await?;
            //println!("{:#?}", remote_changes);
            account.merge(&remote_changes).await?;
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
            tracing::warn!(origin = %self.origin, "skip sync");
            return None;
        }

        tracing::debug!(origin = %self.origin.url);

        let errors = self.execute_sync().await;
        if errors.is_empty() {
            None
        } else {
            let errors = errors
                .into_iter()
                .map(|e| {
                    let origin: Origin = self.origin.clone().into();
                    (origin, e)
                })
                .collect::<Vec<_>>();
            Some(SyncError::Multiple(errors))
        }
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
            sync::RemoteSync, ListenOptions, RemoteBridge, Result,
            WebSocketHandle,
        },
        events::ChangeNotification,
    };

    use std::sync::Arc;
    use tracing::{span, Level};

    // Listen to change notifications and attempt to sync.
    #[cfg(not(target_arch = "wasm32"))]
    impl RemoteBridge {
        async fn on_change_notification(
            bridge: Arc<RemoteBridge>,
            _change: ChangeNotification,
        ) -> Result<()> {
            println!("Got change notification...");

            if let Some(e) = bridge.sync().await {
                tracing::error!(
                    error = ?e,
                    "listen change sync failed",
                );
            }
            Ok(())
        }

        /// Spawn a task that listens for changes
        /// from the remote server and applies any changes
        /// from the remote to the local account.
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
