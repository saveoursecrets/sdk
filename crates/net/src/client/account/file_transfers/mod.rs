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

use futures::FutureExt;
use indexmap::IndexSet;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::{
    collections::HashMap,
    future::Future,
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
        oneshot, watch, Mutex, RwLock, Semaphore,
    },
    time::sleep,
};

mod operations;

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

    /// Inflight notifications channel.
    pub fn notifications(&self) -> &broadcast::Sender<InflightNotification> {
        &self.notifications
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
        /*
        let notify = InflightNotification::TransferRemoved {
            request_id: *request_id,
        };
        */

        let mut inflight = self.inflight.write().await;
        inflight.remove(request_id);

        // notify_listeners(notify, &self.notifications).await;
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
#[derive(Debug)]
enum TransferResult {
    /// Transfer completed across all clients.
    Done,
    /// Operation failed but can be retried.
    Retry,
    /// Fatal error prevents the operation from being retried.
    Fatal(TransferError),
}

/// Settings for file transfer operations.
#[derive(Debug, Clone)]
pub struct FileTransferSettings {
    /// Number of concurrent downloads.
    pub concurrent_downloads: usize,
    /// Number of concurrent uploads.
    pub concurrent_uploads: usize,
    /// Number of concurrent move and delete requests.
    pub concurrent_requests: usize,
    /// Delay in seconds between processing the transfers queue.
    ///
    /// This value is ignored when `debug_assertions` are enabled
    /// so that the tests complete as fast as possible.
    ///
    /// When `debug_assertions` are enabled the delay is one second.
    pub delay_seconds: u64,

    /// Settings for network retry.
    pub retry: NetworkRetry,
}

impl Default for FileTransferSettings {
    fn default() -> Self {
        Self {
            concurrent_downloads: 4,
            concurrent_uploads: 4,
            concurrent_requests: 12,
            delay_seconds: 15,
            // Disable retry for test specs so they
            // execute fast
            #[cfg(debug_assertions)]
            retry: NetworkRetry::new(4, 0),
            // In production use default values
            #[cfg(not(debug_assertions))]
            retry: NetworkRetry::default(),
        }
    }
}

impl FileTransferSettings {
    /// Create file transfer settings with the given
    /// network retry configuration.
    pub fn new_retry(retry: NetworkRetry) -> Self {
        let mut settings = Self::default();
        settings.retry = retry;
        settings
    }
}

/// Transfers files to multiple clients.
///
/// Reads operations from the queue, executes them on
/// the list of clients and removes from the queue only
/// when each operation has been completed on every client.
pub struct FileTransfers {
    paths: Arc<Paths>,
    settings: Arc<FileTransferSettings>,
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
            settings: Arc::new(settings),
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

                            tracing::debug!("file_transfers_shut_down");
                            let _ = shutdown_ack.send(());

                            break;
                        }
                    }
                    _ = Self::maybe_process_transfers(
                      Arc::clone(&paths),
                      Arc::clone(&settings),
                      Arc::clone(&queue),
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
        settings: Arc<FileTransferSettings>,
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
                Arc::clone(&settings),
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
        settings: Arc<FileTransferSettings>,
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
            let mut downloads = Vec::new();
            let mut uploads = Vec::new();
            let mut requests = Vec::new();
            for (file, ops) in list {
                for op in ops {
                    match op {
                        TransferOperation::Download => {
                            downloads.push((file, clients.to_vec()));
                        }
                        TransferOperation::Upload => {
                            uploads.push((file, op, clients.to_vec()));
                        }
                        _ => {
                            requests.push((file, op, clients.to_vec()));
                        }
                    }
                }
            }

            let down: Pin<
                Box<dyn Future<Output = Result<()>> + Send + 'static>,
            > = Box::pin(Self::process_downloads(
                Arc::clone(&paths),
                downloads,
                Arc::clone(&settings),
                Arc::clone(&queue),
                Arc::clone(&inflight_transfers),
            ));

            let up: Pin<
                Box<dyn Future<Output = Result<()>> + Send + 'static>,
            > = Box::pin(Self::process_requests(
                Arc::clone(&paths),
                settings.concurrent_uploads,
                uploads,
                Arc::clone(&settings),
                Arc::clone(&queue),
                Arc::clone(&inflight_transfers),
            ));

            let req: Pin<
                Box<dyn Future<Output = Result<()>> + Send + 'static>,
            > = Box::pin(Self::process_requests(
                Arc::clone(&paths),
                settings.concurrent_requests,
                requests,
                Arc::clone(&settings),
                Arc::clone(&queue),
                Arc::clone(&inflight_transfers),
            ));

            let transfers = vec![up, down, req];
            futures::future::try_join_all(transfers).await?;
        }
        Ok(())
    }

    async fn process_downloads<C>(
        paths: Arc<Paths>,
        downloads: Vec<(ExternalFile, Vec<C>)>,
        settings: Arc<FileTransferSettings>,
        queue: Arc<RwLock<TransfersQueue>>,
        inflight_transfers: Arc<InflightTransfers>,
    ) -> Result<()>
    where
        C: SyncClient + Clone + Send + Sync + 'static,
    {
        let semaphore =
            Arc::new(Semaphore::new(settings.concurrent_downloads));

        let mut jhs = Vec::new();
        for download in downloads {
            let semaphore = semaphore.clone();
            let inflight = Arc::clone(&inflight_transfers);
            let paths = Arc::clone(&paths);
            let settings = Arc::clone(&settings);
            let jh = tokio::task::spawn(async move {
                let (file, clients) = download;
                let _permit = semaphore.acquire().await.unwrap();
                let mut results = Vec::new();
                for client in clients {
                    let request_id = inflight.request_id().await;
                    let result = Self::run_client_operation(
                        request_id,
                        Arc::clone(&settings),
                        file,
                        TransferOperation::Download,
                        Arc::clone(&paths),
                        client,
                        Arc::clone(&inflight),
                    )
                    .await?;

                    let is_done = matches!(&result.2, TransferResult::Done);
                    results.push(result);
                    if is_done {
                        break;
                    }
                }
                drop(_permit);

                Ok::<_, Error>(results)
            });
            jhs.push(jh);
        }

        let mut responses = Vec::new();
        for jh in jhs {
            let response = jh.await.unwrap();
            responses.push(response);
        }

        for response in responses {
            let results = response?;
            for (file, op, result) in results {
                if let TransferResult::Done = result {
                    let mut writer = queue.write().await;
                    writer.transfer_completed(&file, &op).await?;
                    break;
                }
            }
        }

        Ok(())
    }

    async fn process_requests<C>(
        paths: Arc<Paths>,
        concurrency: usize,
        uploads: Vec<(ExternalFile, TransferOperation, Vec<C>)>,
        settings: Arc<FileTransferSettings>,
        queue: Arc<RwLock<TransfersQueue>>,
        inflight_transfers: Arc<InflightTransfers>,
    ) -> Result<()>
    where
        C: SyncClient + Clone + Send + Sync + 'static,
    {
        let semaphore = Arc::new(Semaphore::new(concurrency));

        let mut jhs = Vec::new();
        for upload in uploads {
            let semaphore = semaphore.clone();
            let inflight = Arc::clone(&inflight_transfers);
            let paths = Arc::clone(&paths);
            let settings = Arc::clone(&settings);
            let jh = tokio::task::spawn(async move {
                let (file, op, clients) = upload;
                let mut results = Vec::new();
                let _permit = semaphore.acquire().await.unwrap();
                for client in clients {
                    let request_id = inflight.request_id().await;
                    let result = Self::run_client_operation(
                        request_id,
                        Arc::clone(&settings),
                        file,
                        op,
                        Arc::clone(&paths),
                        client,
                        Arc::clone(&inflight),
                    )
                    .await?;
                    results.push((request_id, result));
                }
                drop(_permit);

                Ok::<_, Error>(results)
            });
            jhs.push(jh);
        }

        let mut responses = Vec::new();
        for jh in jhs {
            let response = jh.await.unwrap();
            responses.push(response);
        }

        for response in responses {
            let results = response?;
            if results
                .iter()
                .all(|(_, (_, _, r))| matches!(r, TransferResult::Done))
            {
                for (_, (file, op, _)) in results {
                    let mut writer = queue.write().await;
                    writer.transfer_completed(&file, &op).await?;
                }
            } else {
                for (request_id, (_, _, result)) in results {
                    if let TransferResult::Fatal(reason) = result {
                        let notify = InflightNotification::TransferError {
                            request_id,
                            reason,
                        };

                        notify_listeners(
                            notify,
                            &inflight_transfers.notifications,
                        )
                        .await;
                    }
                }
            }
        }

        Ok(())
    }

    async fn run_client_operation<C>(
        request_id: u64,
        settings: Arc<FileTransferSettings>,
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

        let retry = settings.retry.clone();

        let result = match &op {
            TransferOperation::Upload => {
                let operation = operations::UploadOperation::new(
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
                let operation = operations::DownloadOperation::new(
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
                let operation = operations::DeleteOperation::new(
                    client,
                    request_id,
                    Arc::clone(&inflight_transfers),
                    retry,
                );
                operation.run(file).await?
            }
            TransferOperation::Move(dest) => {
                let operation = operations::MoveOperation::new(
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

async fn notify_listeners(
    notify: InflightNotification,
    notifier: &broadcast::Sender<InflightNotification>,
) {
    if notifier.receiver_count() > 0 {
        let _ = notifier.send(notify);
    }
}
