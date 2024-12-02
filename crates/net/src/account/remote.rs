//! Connect a remote data source with a local account.
use crate::{
    net::HttpClient,
    protocol::{
        AutoMerge, Origin, RemoteResult, RemoteSync, SyncClient, SyncOptions,
        UpdateSet,
    },
    sdk::{
        account::LocalAccount,
        prelude::Address,
        signer::{ecdsa::BoxedEcdsaSigner, ed25519::BoxedEd25519Signer},
    },
    Result,
};
use async_trait::async_trait;
use sos_protocol::RemoteSyncHandler;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

#[cfg(feature = "files")]
use crate::protocol::transfer::{
    FileOperation, FileSet, FileSyncClient, FileTransferQueueRequest,
    FileTransferQueueSender, TransferOperation,
};

/// Collection of remote targets for synchronization.
pub(crate) type Remotes = HashMap<Origin, RemoteBridge>;

/// Bridge between a local account and a remote.
#[derive(Clone)]
pub struct RemoteBridge {
    /// Address of the account.
    address: Address,
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
        origin: Origin,
        signer: BoxedEcdsaSigner,
        device: BoxedEd25519Signer,
        connection_id: String,
    ) -> Result<Self> {
        let address = signer.address()?;
        let client = HttpClient::new(origin, signer, device, connection_id)?;

        #[cfg(feature = "files")]
        let (file_transfer_queue, _) =
            tokio::sync::broadcast::channel::<FileTransferQueueRequest>(32);

        Ok(Self {
            account,
            client,
            address,
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

    fn client(&self) -> &Self::Client {
        &self.client
    }

    fn origin(&self) -> &Origin {
        self.client.origin()
    }

    fn address(&self) -> &Address {
        &self.address
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
        use sos_sdk::storage::StorageEventLogs;
        let external_files = {
            let account = self.account();
            let account = account.lock().await;
            account.canonical_files().await?
        };

        let file_set = FileSet(external_files);
        let file_transfers = self.client().compare_files(file_set).await?;

        let mut ops = Vec::new();
        for file in file_transfers.uploads.0 {
            ops.push(FileOperation(file, TransferOperation::Upload));
        }

        for file in file_transfers.downloads.0 {
            ops.push(FileOperation(file, TransferOperation::Download));
        }

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

    async fn force_update(
        &self,
        account_data: UpdateSet,
    ) -> RemoteResult<Self::Error> {
        match self
            .client
            .update_account(&self.address, account_data)
            .await
        {
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
    use crate::{
        protocol::ChangeNotification, ListenOptions, RemoteBridge,
        WebSocketHandle,
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
            channel: mpsc::Sender<ChangeNotification>,
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
