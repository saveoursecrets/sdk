//! Connect a remote data source with a local account.
use crate::Result;
use async_trait::async_trait;
use sos_account::LocalAccount;
use sos_core::{AccountId, Origin};
use sos_protocol::{
    network_client::{HttpClient, HttpClientOptions},
    RemoteResult, RemoteSync, SyncClient, SyncOptions,
};
use sos_remote_sync::{AutoMerge, RemoteSyncHandler};
use sos_sync::{SyncDirection, UpdateSet};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

#[cfg(feature = "files")]
use sos_protocol::transfer::{
    FileOperation, FileSet, FileSyncClient, FileTransferQueueRequest,
    FileTransferQueueSender, TransferOperation,
};

/// Collection of remote targets for synchronization.
pub(crate) type Remotes = HashMap<Origin, RemoteBridge>;

/// Bridge between a local account and a remote.
#[derive(Clone)]
pub struct RemoteBridge {
    /// Account identifier.
    account_id: AccountId,
    /// Account so we can replay events
    /// when a remote diff is merged.
    pub(super) account: Arc<Mutex<LocalAccount>>,
    /// Client to use for remote communication.
    pub(crate) client: HttpClient,
    // File transfers.
    #[cfg(feature = "files")]
    pub(crate) file_transfer_queue: FileTransferQueueSender,
}

impl RemoteBridge {
    /// Create a new remote bridge that updates the given
    /// local account.
    pub fn new(
        account: Arc<Mutex<LocalAccount>>,
        options: HttpClientOptions,
    ) -> Result<Self> {
        let account_id = options.account_id;
        let client = HttpClient::new(options)?;

        #[cfg(feature = "files")]
        let (file_transfer_queue, _) =
            tokio::sync::broadcast::channel::<FileTransferQueueRequest>(32);

        Ok(Self {
            account_id,
            account,
            client,
            #[cfg(feature = "files")]
            file_transfer_queue,
        })
    }
}

#[async_trait]
impl RemoteSyncHandler for RemoteBridge {
    type Client = HttpClient;
    type Account = LocalAccount;
    type Error = crate::Error;

    fn direction(&self) -> SyncDirection {
        SyncDirection::Push
    }

    fn client(&self) -> &Self::Client {
        &self.client
    }

    fn origin(&self) -> &Origin {
        self.client.origin()
    }

    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    fn account(&self) -> Arc<Mutex<Self::Account>> {
        self.account.clone()
    }

    #[cfg(feature = "files")]
    fn file_transfer_queue(&self) -> &FileTransferQueueSender {
        &self.file_transfer_queue
    }

    #[cfg(feature = "files")]
    async fn execute_sync_file_transfers(&self) -> Result<()> {
        use sos_sync::StorageEventLogs;
        let external_files = {
            let account = self.account();
            let account = account.lock().await;
            account.canonical_files().await?
        };

        tracing::debug!(
            canonical_len = %external_files.len(),
            "sync_file_transfers",
        );

        let file_set = FileSet(external_files);
        let file_transfers = self.client().compare_files(file_set).await?;

        tracing::debug!(
            uploads_len = %file_transfers.uploads.0.len(),
            downloads_len = %file_transfers.downloads.0.len(),
            "sync_file_transfers",
        );

        let mut ops = Vec::new();
        for file in file_transfers.uploads.0 {
            ops.push(FileOperation(file, TransferOperation::Upload));
        }

        for file in file_transfers.downloads.0 {
            ops.push(FileOperation(file, TransferOperation::Download));
        }

        tracing::debug!(
            operations_len = %ops.len(),
            receiver_count = %self.file_transfer_queue.receiver_count(),
            "sync_file_transfers",
        );

        if !ops.is_empty() && self.file_transfer_queue.receiver_count() > 0 {
            let _ = self.file_transfer_queue.send(ops);
        }

        Ok(())
    }
}

#[async_trait]
impl AutoMerge for RemoteBridge {}

#[async_trait]
impl RemoteSync for RemoteBridge {
    type Error = crate::Error;

    async fn sync(&self) -> RemoteResult<Self::Error> {
        self.sync_with_options(&Default::default()).await
    }

    async fn sync_with_options(
        &self,
        options: &SyncOptions,
    ) -> RemoteResult<Self::Error> {
        match self.execute_sync(options).await {
            Ok(outcome) => RemoteResult {
                origin: self.origin().clone(),
                result: Ok(outcome),
            },
            Err(e) => RemoteResult {
                origin: self.origin().clone(),
                result: Err(e),
            },
        }
    }

    async fn force_update(
        &self,
        account_data: UpdateSet,
    ) -> RemoteResult<Self::Error> {
        match self.client.update_account(account_data).await {
            Ok(_) => RemoteResult {
                origin: self.origin().clone(),
                result: Ok(None),
            },
            Err(e) => RemoteResult {
                origin: self.origin().clone(),
                result: Err(e.into()),
            },
        }
    }

    #[cfg(feature = "files")]
    async fn sync_file_transfers(&self) -> RemoteResult<Self::Error> {
        match self.execute_sync_file_transfers().await {
            Ok(_) => RemoteResult {
                origin: self.origin().clone(),
                result: Ok(None),
            },
            Err(e) => RemoteResult {
                origin: self.origin().clone(),
                result: Err(e),
            },
        }
    }
}

#[cfg(feature = "listen")]
mod listen {
    use crate::RemoteBridge;
    #[cfg(not(target_arch = "wasm32"))]
    use sos_protocol::{
        network_client::{ListenOptions, WebSocketHandle},
        NetworkChangeEvent,
    };
    use tokio::sync::mpsc;

    // Listen to change notifications and attempt to sync.
    #[cfg(not(target_arch = "wasm32"))]
    impl RemoteBridge {
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
            &self,
            options: ListenOptions,
            channel: mpsc::Sender<NetworkChangeEvent>,
        ) -> WebSocketHandle {
            let handle = self.client.listen(options, move |notification| {
                let tx = channel.clone();
                async move {
                    tracing::debug!(notification = ?notification);
                    let _ = tx.send(notification).await;
                }
            });

            handle
        }
    }
}
