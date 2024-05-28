//! Manage pending file transfer operations.
use crate::{
    client::{net::NetworkRetry, Error, Result, SyncClient},
    sdk::{
        storage::files::{
            list_external_files, ExternalFile, FileTransfersSet,
            TransferOperation,
        },
        sync::Origin,
        vfs, Paths,
    },
};

use async_recursion::async_recursion;
use futures::FutureExt;
use http::StatusCode;
use indexmap::IndexSet;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::{
    collections::HashMap,
    future::Future,
    io::ErrorKind,
    path::PathBuf,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    sync::{
        broadcast,
        mpsc::{self, UnboundedReceiver},
        oneshot, watch, Mutex, RwLock,
    },
    time::sleep,
};

/// Channel for upload and download progress notifications.
pub type ProgressChannel = mpsc::Sender<(u64, Option<u64>)>;

/// Channel used to cancel uploads and downloads.
pub type CancelChannel = watch::Sender<()>;

type PendingOperations = HashMap<ExternalFile, IndexSet<TransferOperation>>;

/// Reason for a transfer error notification.
#[derive(Debug, Clone)]
pub enum TransferError {
    /// Error when network retries are exhausted.
    RetryExhausted,
    /// Error when a file that is the target of
    /// an upload or download is no longer on disc.
    TransferFileMissing,
}

/// Notification for inflight transfers.
#[derive(Debug, Clone)]
pub enum InflightNotification {
    /// Notify a transfer was added.
    TransferAdded {
        /// Request identifier.
        request_id: u64,
        /// Server origin.
        origin: Origin,
        /// File information.
        file: ExternalFile,
        /// Transfer operation.
        operation: TransferOperation,
    },
    /// Notify a transfer was updated.
    TransferUpdate {
        /// Request identifier.
        request_id: u64,
        /// Bytes transferred.
        bytes_transferred: u64,
        /// Bytes total.
        bytes_total: Option<u64>,
    },
    /// Notify a transfer was removed.
    TransferRemoved {
        /// Request identifier.
        request_id: u64,
    },
    /// Notify a transfer is being retried.
    TransferRetry {
        /// Request identifier.
        request_id: u64,
        /// Retry number.
        retry: u32,
        /// Maximum number of retries.
        maximum: u32,
    },
    /// Notify a transfer is stopped due to an error.
    TransferError {
        /// Request identifier.
        request_id: u64,
        /// Error reason.
        reason: TransferError,
    },
}

/// Inflight file transfer.
#[derive(Debug)]
pub struct InflightRequest {
    /// Server origin.
    pub origin: Origin,
    /// External file information.
    pub file: ExternalFile,
    /// Transfer operation.
    pub operation: TransferOperation,
    /// Cancel channel for uploads and downloads.
    pub cancel: Option<CancelChannel>,
}

/// Collection of pending transfers.
pub struct InflightTransfers {
    inflight: Arc<RwLock<HashMap<u64, InflightRequest>>>,
    request_id: Arc<Mutex<AtomicU64>>,
    notifications: broadcast::Sender<InflightNotification>,
}

impl InflightTransfers {
    /// Create new pending transfers.
    pub(crate) fn new() -> Self {
        let (notifications, _) = broadcast::channel(2048);
        Self {
            inflight: Arc::new(RwLock::new(Default::default())),
            request_id: Arc::new(Mutex::new(AtomicU64::new(1))),
            notifications,
        }
    }

    /// Determine if the inflight transfers is empty.
    pub async fn is_empty(&self) -> bool {
        let queue = self.inflight.read().await;
        queue.is_empty()
    }

    /// Next request id.
    async fn request_id(&self) -> u64 {
        let id = self.request_id.lock().await;
        id.fetch_add(1, Ordering::SeqCst)
    }

    async fn insert_transfer(
        &self,
        request_id: u64,
        request: InflightRequest,
    ) {
        let notify = InflightNotification::TransferAdded {
            request_id,
            origin: request.origin.clone(),
            file: request.file.clone(),
            operation: request.operation.clone(),
        };

        let mut inflight = self.inflight.write().await;
        inflight.insert(request_id, request);

        notify_listeners(notify, &self.notifications).await;
    }

    async fn remove_transfer(&self, request_id: &u64) {
        let notify = InflightNotification::TransferRemoved {
            request_id: *request_id,
        };

        let mut inflight = self.inflight.write().await;
        inflight.remove(request_id);

        notify_listeners(notify, &self.notifications).await;
    }
}

/// Queue of transfer operations.
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct TransfersQueue {
    #[serde(skip)]
    path: Mutex<PathBuf>,
    #[serde_as(as = "HashMap<DisplayFromStr, _>")]
    #[serde(flatten)]
    queue: PendingOperations,
}

impl TransfersQueue {
    /// Create the transfer list from the external files on disc
    /// if the transfers cache does not exist.
    ///
    /// If the transfers cache already exists it is loaded into memory.
    pub async fn new(paths: &Paths) -> Result<Self> {
        let transfers = paths.file_transfers();
        if vfs::try_exists(&transfers).await? {
            Self::create(transfers.to_owned()).await
        } else {
            let mut cache = Self {
                path: Mutex::new(transfers.to_owned()),
                queue: Default::default(),
            };
            let external_files = list_external_files(paths).await?;
            for file in external_files {
                let mut set = IndexSet::new();
                set.insert(TransferOperation::Upload);
                cache.queue.insert(file, set);
            }
            cache.save().await?;
            Ok(cache)
        }
    }

    /// Create a new transfers queue backed by the given file.
    ///
    /// If the file already exists the queue is loaded from disc.
    async fn create(path: PathBuf) -> Result<Self> {
        let queue = if vfs::try_exists(&path).await? {
            let buf = vfs::read(&path).await?;
            match serde_json::from_slice::<Self>(&buf) {
                Ok(transfers) => transfers.queue,
                Err(e) => {
                    tracing::warn!(error = ?e, "file transfers parse");
                    Default::default()
                }
            }
        } else {
            Default::default()
        };

        Ok(Self {
            path: Mutex::new(path),
            queue,
        })
    }

    /// Number of file transfers in the queue.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Queued transfer operations.
    pub fn queue(&self) -> &PendingOperations {
        &self.queue
    }

    /// Add file transfer operations to the queue.
    pub async fn queue_transfers(
        &mut self,
        ops: PendingOperations,
    ) -> Result<()> {
        for (file, mut operations) in ops {
            let entries = self.queue.entry(file).or_default();
            for op in operations.drain(..) {
                entries.insert(op);
            }
        }
        self.save().await
    }

    /// Mark a transfer operation as completed.
    pub async fn transfer_completed(
        &mut self,
        file: &ExternalFile,
        op: &TransferOperation,
    ) -> Result<()> {
        if let Some(entries) = self.queue.get_mut(file) {
            entries.shift_remove(op);
            if entries.is_empty() {
                self.queue.remove(file);
            }
        }
        self.save().await
    }

    /// Merge file transfers into this transfers queue.
    pub async fn merge_file_transfers(
        &mut self,
        file_transfers: FileTransfersSet,
    ) -> Result<()> {
        for file in file_transfers.uploads.0 {
            let create_entry = {
                if self.queue.get(&file).is_none() {
                    Some(TransferOperation::Upload)
                } else {
                    None
                }
            };
            if let Some(op) = create_entry {
                let mut set = IndexSet::new();
                set.insert(op);
                self.queue.insert(file, set);
            }
        }

        for file in file_transfers.downloads.0 {
            let create_entry = {
                if self.queue.get(&file).is_none() {
                    Some(TransferOperation::Download)
                } else {
                    None
                }
            };
            if let Some(op) = create_entry {
                let mut set = IndexSet::new();
                set.insert(op);
                self.queue.insert(file, set);
            }
        }

        self.save().await
    }

    /// Clear in-memory queued transfers.
    ///
    /// Does not affect the transfer queue stored on disc.
    pub fn clear(&mut self) {
        self.queue.clear();
    }

    /// Save the transfer queue to disc.
    async fn save(&self) -> Result<()> {
        let path = self.path.lock().await;
        let buffer = serde_json::to_vec_pretty(self)?;
        vfs::write(&*path, &buffer).await?;
        Ok(())
    }

    /// Normalize queued operations and write the updated
    /// queue to disc.
    #[doc(hidden)]
    pub async fn normalize(&mut self, paths: Arc<Paths>) -> Result<()> {
        let (deletions, additions) = {
            let mut deletions = Vec::new();
            let mut additions = Vec::new();
            for (file, ops) in &self.queue {
                let path = paths.file_location(
                    file.vault_id(),
                    file.secret_id(),
                    file.file_name().to_string(),
                );
                let ops = ops.iter().collect::<Vec<_>>();

                // Single upload event without a local file to
                // upload can be removed
                if let (true, Some(&TransferOperation::Upload)) =
                    (ops.len() == 1, ops.first())
                {
                    if !vfs::try_exists(&path).await? {
                        deletions.push(*file);
                    }
                }

                // Rewrite a move that no longer
                // exists on disc into an upload of the move
                // destination
                if let Some(&TransferOperation::Move(dest)) = ops.last() {
                    if !vfs::try_exists(&path).await? {
                        // The file may already have been
                        // uploaded to some servers so we
                        // need to add a delete operation
                        // for the old file
                        let mut set = IndexSet::new();
                        set.insert(TransferOperation::Delete);
                        additions.push((*file, set));

                        // Upload operation for the new file
                        let mut set = IndexSet::new();
                        set.insert(TransferOperation::Upload);
                        additions.push((*dest, set));
                    }
                }

                // Rewrite an upload and delete into a delete
                // so that we skip uploads for servers that
                // have yet to receive the file
                if let (
                    true,
                    Some(&TransferOperation::Upload),
                    Some(&TransferOperation::Delete),
                ) = (ops.len() == 2, ops.first(), ops.get(1))
                {
                    if !vfs::try_exists(&path).await? {
                        let mut set = IndexSet::new();
                        set.insert(TransferOperation::Delete);
                        deletions.push(*file);
                        additions.push((*file, set));
                    }
                }
            }
            (deletions, additions)
        };

        for file in deletions {
            self.queue.remove(&file);
        }
        for (file, ops) in additions {
            self.queue.insert(file, ops);
        }

        self.save().await?;

        Ok(())
    }
}

/// Result of a file transfer operation.
enum TransferResult {
    /// Transfer completed across all clients.
    Done,
    /// Operation failed but can be retried.
    Retry,
    /// Fatal error prevents the operation from being retried.
    Fatal(TransferError),
}

/// Settings for file transfer operations.
pub struct FileTransferSettings {
    /// Number of concurrent transfers.
    pub concurrent_transfers: usize,
    /// Delay in seconds between processing the transfers queue.
    ///
    /// This value is ignored when `debug_assertions` are enabled
    /// so that the tests complete as fast as possible.
    ///
    /// When `debug_assertions` are enabled the delay is one second.
    pub delay_seconds: u64,
}

impl Default for FileTransferSettings {
    fn default() -> Self {
        Self {
            concurrent_transfers: 4,
            delay_seconds: 15,
        }
    }
}

/// Transfers files to multiple clients.
///
/// Reads operations from the queue, executes them on
/// the list of clients and removes from the queue only
/// when each operation has been completed on every client.
pub struct FileTransfers {
    paths: Arc<Paths>,
    settings: FileTransferSettings,
    shutdown: UnboundedReceiver<()>,
    shutdown_ack: oneshot::Sender<()>,
}

impl FileTransfers {
    /// Create new file transfers manager.
    pub fn new(
        paths: Arc<Paths>,
        settings: FileTransferSettings,
        shutdown: UnboundedReceiver<()>,
        shutdown_ack: oneshot::Sender<()>,
    ) -> Self {
        Self {
            paths,
            settings,
            shutdown,
            shutdown_ack,
        }
    }

    /// Spawn a task to transfer file operations.
    pub fn run<C>(
        self,
        queue: Arc<RwLock<TransfersQueue>>,
        inflight_transfers: Arc<InflightTransfers>,
        clients: Vec<C>,
    ) where
        C: SyncClient + Clone + Send + Sync + 'static,
    {
        let paths = self.paths;
        let settings = self.settings;
        let mut shutdown = self.shutdown;
        let shutdown_ack = self.shutdown_ack;

        tokio::task::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    signal = shutdown.recv().fuse() => {
                        if signal.is_some() {
                            tracing::debug!("file_transfers_shutting_down");

                            /*
                            // Wait for any pending writes to disc
                            // for a graceful shutdown
                            let transfers = queue.read().await;
                            let _ = transfers.path.lock().await;
                            */

                            tracing::debug!("file_transfers_shut_down");
                            let _ = shutdown_ack.send(());

                            break;
                        }
                    }
                    _ = Self::maybe_process_transfers(
                      Arc::clone(&paths),
                      &settings, Arc::clone(&queue),
                      Arc::clone(&inflight_transfers),
                      clients.as_slice(),
                    ).fuse() => {}
                }
            }
        });
    }

    /// Try to process the pending transfers list.
    async fn maybe_process_transfers<C>(
        paths: Arc<Paths>,
        settings: &FileTransferSettings,
        queue: Arc<RwLock<TransfersQueue>>,
        inflight_transfers: Arc<InflightTransfers>,
        clients: &[C],
    ) -> Result<()>
    where
        C: SyncClient + Clone + Send + Sync + 'static,
    {
        let pending_transfers = {
            let mut writer = queue.write().await;
            if let Err(e) = writer.normalize(Arc::clone(&paths)).await {
                tracing::error!(error = ?e);
            }
            writer.queue.clone()
        };

        #[cfg(not(debug_assertions))]
        tracing::debug!(
            num_pending = pending_transfers.len(),
            "pending_transfers",
        );

        if !pending_transfers.is_empty() {
            // Try to process pending transfers
            if let Err(e) = Self::try_process_transfers(
                Arc::clone(&paths),
                &settings,
                Arc::clone(&queue),
                Arc::clone(&inflight_transfers),
                clients,
                pending_transfers,
            )
            .await
            {
                tracing::warn!(error = ?e);
            }
        }

        #[cfg(debug_assertions)]
        sleep(Duration::from_secs(1)).await;

        #[cfg(not(debug_assertions))]
        sleep(Duration::from_secs(settings.delay_seconds)).await;

        Ok(())
    }

    /// Try to process the pending transfers list.
    async fn try_process_transfers<C>(
        paths: Arc<Paths>,
        settings: &FileTransferSettings,
        queue: Arc<RwLock<TransfersQueue>>,
        inflight_transfers: Arc<InflightTransfers>,
        clients: &[C],
        pending_transfers: PendingOperations,
    ) -> Result<()>
    where
        C: SyncClient + Clone + Send + Sync + 'static,
    {
        if !clients.is_empty() {
            let list = pending_transfers.into_iter().collect::<Vec<_>>();

            let chunk_size = if clients.len() < settings.concurrent_transfers
            {
                settings.concurrent_transfers / clients.len()
            } else {
                settings.concurrent_transfers
            };

            for files in list.chunks(chunk_size) {
                let mut futures = Vec::new();
                for (file, ops) in files {
                    futures.push(Self::process_operations(
                        *file,
                        ops.clone(),
                        Arc::clone(&paths),
                        Arc::clone(&queue),
                        Arc::clone(&inflight_transfers),
                        clients.to_vec(),
                    ));
                }
                futures::future::try_join_all(futures).await?;
            }
        }
        Ok(())
    }

    async fn process_operations<C>(
        file: ExternalFile,
        operations: IndexSet<TransferOperation>,
        paths: Arc<Paths>,
        queue: Arc<RwLock<TransfersQueue>>,
        inflight_transfers: Arc<InflightTransfers>,
        clients: Vec<C>,
    ) -> Result<()>
    where
        C: SyncClient + Clone + Send + Sync + 'static,
    {
        for op in operations {
            // Split uploads and downloads as they require different
            // handling.
            //
            // Uploads must be successful for all remote servers whilst
            // a download only needs to execute successfully against a
            // single server.
            let mut uploads = Vec::new();
            let mut downloads = Vec::new();

            for client in &clients {
                let request_id = inflight_transfers.request_id().await;
                if let TransferOperation::Download = &op {
                    downloads.push(Self::run_client_operation(
                        request_id,
                        file,
                        op,
                        Arc::clone(&paths),
                        client.clone(),
                        Arc::clone(&inflight_transfers),
                    ));
                } else {
                    uploads.push(Self::run_client_operation(
                        request_id,
                        file,
                        op,
                        Arc::clone(&paths),
                        client.clone(),
                        Arc::clone(&inflight_transfers),
                    ));
                }
            }

            // Process uploads and downloads concurrently
            let up: Pin<
                Box<dyn Future<Output = Result<()>> + Send + 'static>,
            > = Box::pin(Self::process_uploads(Arc::clone(&queue), uploads));
            let down: Pin<
                Box<dyn Future<Output = Result<()>> + Send + 'static>,
            > = Box::pin(Self::process_downloads(
                Arc::clone(&queue),
                downloads,
            ));

            let transfers = vec![up, down];
            futures::future::try_join_all(transfers).await?;
        }

        Ok(())
    }

    async fn process_uploads(
        queue: Arc<RwLock<TransfersQueue>>,
        uploads: Vec<
            impl Future<
                    Output = Result<(
                        ExternalFile,
                        TransferOperation,
                        TransferResult,
                    )>,
                > + Send
                + 'static,
        >,
    ) -> Result<()> {
        // Execute the client requests
        let results = futures::future::try_join_all(uploads).await?;

        // Collate results that completed for all clients
        let mut collated = HashMap::new();
        for (file, op, result) in results {
            let entry = collated.entry((file, op)).or_insert(vec![]);
            entry.push(result);
        }

        // Mark transfers that were successful for all clients
        // as completed, removing them from the queue
        for ((file, op), results) in collated {
            if results.iter().all(|result| {
                matches!(
                    result,
                    TransferResult::Done | TransferResult::Fatal(_)
                )
            }) {
                let mut writer = queue.write().await;
                writer.transfer_completed(&file, &op).await?;
            }
        }
        Ok(())
    }

    async fn process_downloads(
        queue: Arc<RwLock<TransfersQueue>>,
        downloads: Vec<
            impl Future<
                    Output = Result<(
                        ExternalFile,
                        TransferOperation,
                        TransferResult,
                    )>,
                > + Send
                + 'static,
        >,
    ) -> Result<()> {
        for fut in downloads {
            let (file, op, result) = fut.await?;
            match result {
                TransferResult::Done | TransferResult::Fatal(_) => {
                    let mut writer = queue.write().await;
                    writer.transfer_completed(&file, &op).await?;
                    return Ok(());
                }
                _ => {}
            }
        }

        // Retry the download on the next
        // loop iteration if the download
        // failed on all servers
        Ok(())
    }

    async fn run_client_operation<C>(
        request_id: u64,
        file: ExternalFile,
        op: TransferOperation,
        paths: Arc<Paths>,
        client: C,
        inflight_transfers: Arc<InflightTransfers>,
    ) -> Result<(ExternalFile, TransferOperation, TransferResult)>
    where
        C: SyncClient + Clone + Send + Sync + 'static,
    {
        let (progress_tx, cancel_tx, cancel_rx) =
            if let TransferOperation::Upload | TransferOperation::Download =
                &op
            {
                let (cancel_tx, cancel_rx) = watch::channel::<()>(());
                let (progress_tx, mut progress_rx): (ProgressChannel, _) =
                    mpsc::channel(16);

                let progress_transfers = Arc::clone(&inflight_transfers);

                // Proxt the progress information for an individual
                // upload or download to the inflight transfers
                // notification channel
                tokio::task::spawn(async move {
                    while let Some(event) = progress_rx.recv().await {
                        let notify = InflightNotification::TransferUpdate {
                            request_id,
                            bytes_transferred: event.0,
                            bytes_total: event.1,
                        };
                        notify_listeners(
                            notify,
                            &progress_transfers.notifications,
                        )
                        .await;
                    }
                });

                (Some(progress_tx), Some(cancel_tx), Some(cancel_rx))
            } else {
                (None, None, None)
            };

        {
            let request = InflightRequest {
                origin: client.origin().clone(),
                file,
                operation: op,
                cancel: cancel_tx,
            };

            tracing::debug!(
                request_id = %request_id,
                "inflight_transfer::insert",
            );

            inflight_transfers
                .insert_transfer(request_id, request)
                .await;
        }

        tracing::trace!(
          op = ?op,
          url = %client.origin().url(),
          "file_transfer"
        );

        let retry = NetworkRetry::default();
        let result = match &op {
            TransferOperation::Upload => {
                let operation = UploadOperation::new(
                    client,
                    paths,
                    request_id,
                    Arc::clone(&inflight_transfers),
                    retry,
                );
                let progress_tx = progress_tx.unwrap();
                let cancel_rx = cancel_rx.unwrap();
                operation.run(file, progress_tx, cancel_rx).await?
            }
            TransferOperation::Download => {
                let operation = DownloadOperation::new(
                    client,
                    paths,
                    request_id,
                    Arc::clone(&inflight_transfers),
                    retry,
                );
                let progress_tx = progress_tx.unwrap();
                let cancel_rx = cancel_rx.unwrap();
                operation.run(file, progress_tx, cancel_rx).await?
            }
            TransferOperation::Delete => {
                let operation = DeleteOperation::new(
                    client,
                    request_id,
                    Arc::clone(&inflight_transfers),
                    retry,
                );
                operation.run(file).await?
            }
            TransferOperation::Move(dest) => {
                let operation = MoveOperation::new(
                    client,
                    request_id,
                    Arc::clone(&inflight_transfers),
                    retry,
                );
                operation.run(file, dest).await?
            }
        };

        if let TransferResult::Fatal(reason) = &result {
            // Handle backpressure on notifications
            let notify = InflightNotification::TransferError {
                request_id,
                reason: reason.clone(),
            };

            notify_listeners(notify, &inflight_transfers.notifications).await;
        }

        {
            tracing::debug!(
                request_id = %request_id,
                "inflight_transfer::remove",
            );
            inflight_transfers.remove_transfer(&request_id).await;
        }

        Ok((file, op, result))
    }
}

struct UploadOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    client: C,
    paths: Arc<Paths>,
    request_id: u64,
    inflight: Arc<InflightTransfers>,
    retry: NetworkRetry,
}

impl<C> UploadOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    fn new(
        client: C,
        paths: Arc<Paths>,
        request_id: u64,
        inflight: Arc<InflightTransfers>,
        retry: NetworkRetry,
    ) -> Self {
        Self {
            client,
            paths,
            request_id,
            inflight,
            retry,
        }
    }

    #[async_recursion]
    async fn run(
        &self,
        file: ExternalFile,
        progress_tx: ProgressChannel,
        cancel_rx: watch::Receiver<()>,
    ) -> Result<TransferResult> {
        let path = self.paths.file_location(
            file.vault_id(),
            file.secret_id(),
            file.file_name().to_string(),
        );

        let result = match self
            .client
            .upload_file(&file, &path, progress_tx.clone(), cancel_rx.clone())
            .await
        {
            Ok(status) => self.on_response(status),
            Err(e) => self.on_error(e),
        };

        if let TransferResult::Retry = result {
            let retries = self.retry.increment().await;

            tracing::debug!(retries = %retries, "upload_file::retry");
            self.notify_retry(retries - 1, self.retry.maximum_retries)
                .await;

            if self.retry.is_exhausted(retries) {
                tracing::debug!(
                  maximum_retries = %self.retry.maximum_retries,
                  "upload_file::retries_exhausted");
                return Ok(TransferResult::Fatal(
                    TransferError::RetryExhausted,
                ));
            }

            self.retry
                .wait_and_retry(retries, async move {
                    self.run(file, progress_tx, cancel_rx).await
                })
                .await?
        } else {
            Ok(result)
        }
    }
}

impl<C> TransferTask for UploadOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    fn request_id(&self) -> u64 {
        self.request_id
    }

    fn inflight(&self) -> &InflightTransfers {
        &*self.inflight
    }

    fn on_response(&self, status: StatusCode) -> TransferResult {
        if status == StatusCode::OK || status == StatusCode::NOT_MODIFIED {
            TransferResult::Done
        } else {
            TransferResult::Retry
        }
    }

    fn on_error(&self, error: Error) -> TransferResult {
        tracing::warn!(error = ?error, "upload_file::error");
        on_error(error)
    }
}

struct DownloadOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    client: C,
    paths: Arc<Paths>,
    request_id: u64,
    inflight: Arc<InflightTransfers>,
    retry: NetworkRetry,
}

impl<C> DownloadOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    fn new(
        client: C,
        paths: Arc<Paths>,
        request_id: u64,
        inflight: Arc<InflightTransfers>,
        retry: NetworkRetry,
    ) -> Self {
        Self {
            client,
            paths,
            request_id,
            inflight,
            retry,
        }
    }

    #[async_recursion]
    async fn run(
        &self,
        file: ExternalFile,
        progress_tx: ProgressChannel,
        cancel_rx: watch::Receiver<()>,
    ) -> Result<TransferResult> {
        // Ensure the parent directory for the download exists
        let parent_path = self
            .paths
            .file_folder_location(file.vault_id())
            .join(file.secret_id().to_string());

        if !vfs::try_exists(&parent_path).await? {
            vfs::create_dir_all(&parent_path).await?;
        }

        // Fetch the file
        let path = self.paths.file_location(
            file.vault_id(),
            file.secret_id(),
            file.file_name().to_string(),
        );

        let result = match self
            .client
            .download_file(
                &file,
                &path,
                progress_tx.clone(),
                cancel_rx.clone(),
            )
            .await
        {
            Ok(status) => self.on_response(status),
            Err(e) => self.on_error(e),
        };

        if let TransferResult::Retry = result {
            let retries = self.retry.increment().await;

            tracing::debug!(retries = %retries, "download_file::retry");
            self.notify_retry(retries - 1, self.retry.maximum_retries)
                .await;

            if self.retry.is_exhausted(retries) {
                tracing::debug!(
                  maximum_retries = %self.retry.maximum_retries,
                  "download_file::retries_exhausted");
                return Ok(TransferResult::Fatal(
                    TransferError::RetryExhausted,
                ));
            }

            self.retry
                .wait_and_retry(retries, async move {
                    self.run(file, progress_tx, cancel_rx).await
                })
                .await?
        } else {
            Ok(result)
        }
    }
}

impl<C> TransferTask for DownloadOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    fn request_id(&self) -> u64 {
        self.request_id
    }

    fn inflight(&self) -> &InflightTransfers {
        &*self.inflight
    }

    fn on_response(&self, status: StatusCode) -> TransferResult {
        if status == StatusCode::OK {
            TransferResult::Done
        } else {
            TransferResult::Retry
        }
    }

    fn on_error(&self, error: Error) -> TransferResult {
        tracing::warn!(error = ?error, "download_file::error");
        on_error(error)
    }
}

struct DeleteOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    client: C,
    request_id: u64,
    inflight: Arc<InflightTransfers>,
    retry: NetworkRetry,
}

impl<C> DeleteOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    fn new(
        client: C,
        request_id: u64,
        inflight: Arc<InflightTransfers>,
        retry: NetworkRetry,
    ) -> Self {
        Self {
            client,
            request_id,
            inflight,
            retry,
        }
    }

    #[async_recursion]
    async fn run(&self, file: ExternalFile) -> Result<TransferResult> {
        let result = match self.client.delete_file(&file).await {
            Ok(status) => self.on_response(status),
            Err(e) => self.on_error(e),
        };

        if let TransferResult::Retry = result {
            let retries = self.retry.increment().await;

            tracing::debug!(retries = %retries, "delete_file::retry");
            self.notify_retry(retries - 1, self.retry.maximum_retries)
                .await;

            if self.retry.is_exhausted(retries) {
                tracing::debug!(
                  maximum_retries = %self.retry.maximum_retries,
                  "delete_file::retries_exhausted");
                return Ok(TransferResult::Fatal(
                    TransferError::RetryExhausted,
                ));
            }

            self.retry
                .wait_and_retry(retries, async move { self.run(file).await })
                .await?
        } else {
            Ok(result)
        }
    }
}

impl<C> TransferTask for DeleteOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    fn request_id(&self) -> u64 {
        self.request_id
    }

    fn inflight(&self) -> &InflightTransfers {
        &*self.inflight
    }

    fn on_response(&self, status: StatusCode) -> TransferResult {
        if status == StatusCode::OK || status == StatusCode::NOT_FOUND {
            TransferResult::Done
        } else {
            TransferResult::Retry
        }
    }

    fn on_error(&self, error: Error) -> TransferResult {
        tracing::warn!(error = ?error, "delete_file::error");
        on_error(error)
    }
}

struct MoveOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    client: C,
    request_id: u64,
    inflight: Arc<InflightTransfers>,
    retry: NetworkRetry,
}

impl<C> MoveOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    fn new(
        client: C,
        request_id: u64,
        inflight: Arc<InflightTransfers>,
        retry: NetworkRetry,
    ) -> Self {
        Self {
            client,
            request_id,
            inflight,
            retry,
        }
    }

    #[async_recursion]
    async fn run(
        &self,
        file: ExternalFile,
        dest: &ExternalFile,
    ) -> Result<TransferResult> {
        let result = match self.client.move_file(&file, dest).await {
            Ok(status) => self.on_response(status),
            Err(e) => self.on_error(e),
        };

        if let TransferResult::Retry = result {
            let retries = self.retry.increment().await;

            tracing::debug!(retries = %retries, "move_file::retry");
            self.notify_retry(retries - 1, self.retry.maximum_retries)
                .await;

            if self.retry.is_exhausted(retries) {
                tracing::debug!(
                  maximum_retries = %self.retry.maximum_retries,
                  "move_file::retries_exhausted");
                return Ok(TransferResult::Fatal(
                    TransferError::RetryExhausted,
                ));
            }

            self.retry
                .wait_and_retry(
                    retries,
                    async move { self.run(file, dest).await },
                )
                .await?
        } else {
            Ok(result)
        }
    }
}

impl<C> TransferTask for MoveOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    fn request_id(&self) -> u64 {
        self.request_id
    }

    fn inflight(&self) -> &InflightTransfers {
        &*self.inflight
    }

    fn on_response(&self, status: StatusCode) -> TransferResult {
        if status == StatusCode::OK {
            TransferResult::Done
        } else {
            TransferResult::Retry
        }
    }

    fn on_error(&self, error: Error) -> TransferResult {
        tracing::warn!(error = ?error, "move_file::error");
        on_error(error)
    }
}

trait TransferTask {
    fn on_response(&self, status: StatusCode) -> TransferResult;
    fn on_error(&self, error: Error) -> TransferResult;
    fn inflight(&self) -> &InflightTransfers;
    fn request_id(&self) -> u64;

    async fn notify_retry(&self, retry: u32, maximum: u32) {
        let notify = InflightNotification::TransferRetry {
            request_id: self.request_id(),
            retry,
            maximum,
        };
        notify_listeners(notify, &self.inflight().notifications).await;
    }
}

fn on_error(error: Error) -> TransferResult {
    match error {
        Error::Io(io) => match io.kind() {
            ErrorKind::NotFound => {
                TransferResult::Fatal(TransferError::TransferFileMissing)
            }
            _ => TransferResult::Retry,
        },
        _ => TransferResult::Retry,
    }
}

async fn notify_listeners(
    notify: InflightNotification,
    notifier: &broadcast::Sender<InflightNotification>,
) {
    let mut result = notifier.send(notify);
    while let Err(err) = result {
        sleep(Duration::from_millis(32)).await;
        result = notifier.send(err.0);
    }
}
