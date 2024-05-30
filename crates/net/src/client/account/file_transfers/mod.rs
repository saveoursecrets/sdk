//! Queue file transfer operations and spawn tasks to
//! perform the file transfer operations..
use crate::{
    client::{net::NetworkRetry, Error, Result, SyncClient},
    sdk::{
        storage::files::{ExternalFile, TransferOperation},
        vfs, Paths,
    },
};

use futures::FutureExt;
use std::sync::Arc;
use tokio::sync::{
    broadcast, mpsc, oneshot, watch, Mutex, RwLock, Semaphore,
};

mod inflight;
mod operations;

pub use inflight::{
    InflightNotification, InflightRequest, InflightTransfers,
};
use std::collections::{HashSet, VecDeque};

/// Request to queue a file transfer.
pub type FileTransferQueueRequest = Vec<(ExternalFile, TransferOperation)>;

/// Channel for upload and download progress notifications.
pub type ProgressChannel = mpsc::Sender<(u64, Option<u64>)>;

/// Channel used to cancel uploads and downloads.
pub type CancelChannel = watch::Sender<()>;

/// Reason for a transfer error notification.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum TransferError {
    /// Error when network retries are exhausted.
    RetryExhausted,
    /// Error when a file that is the target of
    /// an upload or download is no longer on disc.
    TransferFileMissing,
    /// Error when the target file for a move operation is missing.
    MovedMissing,
    /// Transfer was canceled.
    Canceled,
}

/// Result of a file transfer operation.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
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
    /// Number of concurrent requests.
    pub concurrent_requests: usize,
    /// Settings for network retry.
    pub retry: NetworkRetry,
}

impl Default for FileTransferSettings {
    fn default() -> Self {
        Self {
            concurrent_requests: 4,
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

pub(crate) struct FileTransfersHandle {
    shutdown_tx: mpsc::Sender<()>,
    shutdown_rx: oneshot::Receiver<()>,
    pub(crate) queue_tx: mpsc::Sender<FileTransferQueueRequest>,
}

impl FileTransfersHandle {
    /// Create a new handle.
    fn new() -> (
        Self,
        mpsc::Receiver<()>,
        oneshot::Sender<()>,
        mpsc::Receiver<FileTransferQueueRequest>,
    ) {
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
        let (ack_tx, ack_rx) = oneshot::channel::<()>();
        let (queue_tx, queue_rx) =
            mpsc::channel::<FileTransferQueueRequest>(32);

        (
            Self {
                shutdown_tx,
                shutdown_rx: ack_rx,
                queue_tx,
            },
            shutdown_rx,
            ack_tx,
            queue_rx,
        )
    }

    /// Send a collection of items to be added to the queue.
    pub async fn send(&self, items: FileTransferQueueRequest) {
        let res = self.queue_tx.send(items).await;
        if let Err(error) = res {
            tracing::warn!(error = ?error);
        }
    }

    /// Shutdown the file transfers loop.
    pub async fn shutdown(self) {
        let res = self.shutdown_tx.send(()).await;
        if let Err(error) = res {
            tracing::warn!(error = ?error);
        }
        let res = self.shutdown_rx.await;
        if let Err(error) = res {
            tracing::warn!(error = ?error);
        }
    }
}

/// Transfers files to multiple clients.
///
/// Reads operations from the queue, executes them on
/// the list of clients and removes from the queue only
/// when each operation has been completed on every client.
pub struct FileTransfers<C>
where
    C: SyncClient + Clone + Send + Sync + PartialEq + 'static,
{
    clients: Arc<Mutex<Vec<C>>>,
    settings: Arc<FileTransferSettings>,
    pub(crate) queue:
        Arc<RwLock<VecDeque<(ExternalFile, TransferOperation)>>>,
    pub(crate) inflight: Arc<InflightTransfers>,
}

impl<C> FileTransfers<C>
where
    C: SyncClient + Clone + Send + Sync + PartialEq + 'static,
{
    /// Create new file transfers manager.
    pub fn new(clients: Vec<C>, settings: FileTransferSettings) -> Self {
        let queue = VecDeque::new();
        let inflight = InflightTransfers::new();

        Self {
            clients: Arc::new(Mutex::new(clients)),
            settings: Arc::new(settings),
            queue: Arc::new(RwLock::new(queue)),
            inflight: Arc::new(inflight),
        }
    }

    /// Add a client for file transfer operations.
    pub async fn add_client(&self, client: C) {
        let mut writer = self.clients.lock().await;
        writer.push(client);
        println!("Added a new client...");
    }

    /// Add a client for file transfer operations.
    pub async fn remove_client(&self, client: &C) {
        let mut writer = self.clients.lock().await;
        if let Some(pos) = writer.iter().position(|c| c == client) {
            writer.remove(pos);
        }
    }

    /// Spawn a task to transfer file operations.
    pub fn run(&mut self, paths: Arc<Paths>) -> FileTransfersHandle {
        let (handle, mut shutdown_rx, shutdown_tx, mut queue_rx) =
            FileTransfersHandle::new();

        let queue_drained = Arc::new(Mutex::new(false));

        let clients = self.clients.clone();
        let queue = self.queue.clone();
        let inflight = self.inflight.clone();
        let cancel_inflight = self.inflight.clone();
        let settings = self.settings.clone();
        let semaphore =
            Arc::new(Semaphore::new(self.settings.concurrent_requests));

        tokio::task::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    signal = shutdown_rx.recv().fuse() => {
                        if signal.is_some() {
                            tracing::debug!("file_transfers::shutting_down");

                            // Clear the queue to break the main
                            // task loop
                            let mut writer = queue.write().await;
                            *writer = Default::default();

                            // Cancel any inflight transfers
                            cancel_inflight.cancel().await;

                            let _ = shutdown_tx.send(());
                            tracing::debug!("file_transfers::shut_down");

                            break;
                        }
                    }
                    Some(events) = queue_rx.recv() => {
                        // println!("queue events: {}", events.len());

                        let num_queued = {
                            let mut writer = queue.write().await;
                            for event in events {
                                if !writer.contains(&event) {
                                  writer.push_front(event);
                                }
                            }
                            writer.len()
                        };

                        let is_running = {
                          let reader = queue_drained.lock().await;
                          *reader
                        };

                        if num_queued > 0 && !is_running {
                          {
                            let mut writer = queue_drained.lock().await;
                            *writer = true;
                          }

                          let semaphore = semaphore.clone();
                          let queue = queue.clone();
                          let inflight = inflight.clone();
                          let settings = settings.clone();
                          let paths = paths.clone();
                          let drained = queue_drained.clone();

                          // Clone of the current client list which
                          // will remain fixed until the current queue
                          // is completely drained
                          let clients = {
                            let reader = clients.lock().await;
                            reader.iter().cloned().collect::<Vec<_>>()
                          };

                          if !clients.is_empty() {
                              // We must not block here otherwise we can't cancel
                              // whilst there are inflight requests as this branch
                              // of the select would block the cancel branch
                              tokio::task::spawn(async move {

                                // This will complete when the queue
                                // is empty
                                let res = Self::spawn_tasks(
                                    paths.clone(),
                                    semaphore.clone(),
                                    queue.clone(),
                                    inflight.clone(),
                                    settings.clone(),
                                    clients.clone(),
                                )
                                .await;
                                if let Err(error) = res {
                                  tracing::error!(error = ?error);
                                }

                                // Reset so we can spawn another task
                                let mut writer = drained.lock().await;
                                *writer = false;

                              });
                          }

                        }
                    }
                }
            }

            Ok::<_, Error>(())
        });

        handle
    }

    async fn spawn_tasks(
        paths: Arc<Paths>,
        semaphore: Arc<Semaphore>,
        queue: Arc<RwLock<VecDeque<(ExternalFile, TransferOperation)>>>,
        inflight: Arc<InflightTransfers>,
        settings: Arc<FileTransferSettings>,
        clients: Vec<C>,
    ) -> Result<()> {
        let mut remaining = Self::consume_queue(
            paths.clone(),
            semaphore.clone(),
            queue.clone(),
            inflight.clone(),
            settings.clone(),
            clients.as_slice(),
        )
        .await?;

        while let Some(_) = remaining {
            remaining = Self::consume_queue(
                paths.clone(),
                semaphore.clone(),
                queue.clone(),
                inflight.clone(),
                settings.clone(),
                clients.as_slice(),
            )
            .await?;
        }

        Ok(())
    }

    async fn consume_queue(
        paths: Arc<Paths>,
        semaphore: Arc<Semaphore>,
        queue: Arc<RwLock<VecDeque<(ExternalFile, TransferOperation)>>>,
        inflight: Arc<InflightTransfers>,
        settings: Arc<FileTransferSettings>,
        clients: &[C],
    ) -> Result<Option<()>> {
        let mut requests = Vec::new();
        let mut downloads = Vec::new();

        loop {
            let len = {
                let queue = queue.read().await;
                queue.len()
            };

            if semaphore.available_permits() == 0 || len == 0 {
                break;
            }

            let item = {
                let mut queue = queue.write().await;
                queue.pop_front()
            };

            if let Some((file, op)) = item {
                // println!("process: {:#?}", op);
                tracing::debug!(
                  file = ?file, op = ?op, "file_transfers::queue");

                match op {
                    // Downloads are a special case that can complete
                    // on the first successful operation
                    TransferOperation::Download => {
                        let inflight = inflight.clone();
                        let settings = settings.clone();
                        let paths = paths.clone();
                        let clients = clients.to_vec().clone();
                        let permit = semaphore.clone();
                        let jh = tokio::task::spawn(async move {
                            let mut results = Vec::new();
                            for client in clients {
                                let _permit = permit.acquire().await.unwrap();
                                let request_id = inflight.request_id().await;

                                let result = Self::run_client_operation(
                                    request_id,
                                    file,
                                    op,
                                    client.clone(),
                                    settings.clone(),
                                    paths.clone(),
                                    inflight.clone(),
                                )
                                .await?;

                                let is_done =
                                    matches!(&result.2, TransferResult::Done);
                                results.push((request_id, result));
                                if is_done {
                                    break;
                                }
                            }
                            Ok::<_, Error>(results)
                        });
                        downloads.push(jh);
                    }
                    // Other operations must complete on all clients
                    _ => {
                        for client in clients.to_vec() {
                            let inflight = inflight.clone();
                            let settings = settings.clone();
                            let paths = paths.clone();
                            let permit = semaphore.clone();
                            let jh = tokio::task::spawn(async move {
                                let _permit = permit.acquire().await.unwrap();
                                let request_id = inflight.request_id().await;

                                let result = Self::run_client_operation(
                                    request_id,
                                    file,
                                    op,
                                    client.clone(),
                                    settings.clone(),
                                    paths.clone(),
                                    inflight.clone(),
                                )
                                .await?;

                                Ok::<_, Error>((request_id, result))
                            });
                            requests.push(jh);
                        }
                    }
                }
            }
        }

        let request_paths = paths.clone();
        let request_queue = queue.clone();
        let download_inflight = inflight.clone();
        let download_queue = queue.clone();

        let requests_task = async move {
            let mut results = Vec::new();
            for jh in requests {
                let result = jh.await.unwrap()?;
                results.push(result);
            }

            let done = results
                .iter()
                .all(|(_, (_, _, r))| matches!(r, TransferResult::Done));

            if done {
                for (request_id, _) in results {
                    let notify =
                        InflightNotification::TransferDone { request_id };
                    notify_listeners(notify, &inflight.notifications).await;
                }
            } else {
                // println!("result: {:#?}", results);

                // If we attempt a move but the source file
                // of the move is missing on the target server
                // and we have the destination locally
                // on disc then we mutate it into an update operation
                let moved_missing = results
                    .iter()
                    .filter(|(_, (_, _, r))| {
                        matches!(
                            r,
                            TransferResult::Fatal(
                                TransferError::MovedMissing
                            )
                        )
                    })
                    .cloned()
                    .collect::<HashSet<_>>();
                for (_, (_, op, _)) in moved_missing {
                    if let TransferOperation::Move(dest) = &op {
                        let path = request_paths.file_location(
                            dest.vault_id(),
                            dest.secret_id(),
                            dest.file_name().to_string(),
                        );

                        if vfs::try_exists(path).await? {
                            let item =
                                (dest.clone(), TransferOperation::Upload);
                            let mut queue = request_queue.write().await;
                            if !queue.contains(&item) {
                                queue.push_back(item);
                            }
                        }
                    }
                }

                for (file, op) in results
                    .into_iter()
                    .filter(|(_, (_, _, r))| {
                        matches!(
                            r,
                            TransferResult::Fatal(
                                TransferError::RetryExhausted
                            )
                        )
                    })
                    .map(|(_, (file, op, _))| (file, op))
                {
                    let item = (file, op);
                    let mut queue = request_queue.write().await;
                    if !queue.contains(&item) {
                        queue.push_back(item);
                    }
                }
            }

            Ok::<_, Error>(())
        };

        let downloads_task = async move {
            let mut results = Vec::new();
            for jh in downloads {
                let result = jh.await.unwrap()?;
                results.push(result);
            }

            let results = results.into_iter().flatten().collect::<Vec<_>>();

            let done_requests = results
                .iter()
                .filter_map(|(id, (_, _, r))| {
                    if matches!(r, TransferResult::Done) {
                        Some(id)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();

            if let Some(request_id) = done_requests.first() {
                let notify = InflightNotification::TransferDone {
                    request_id: **request_id,
                };
                notify_listeners(notify, &download_inflight.notifications)
                    .await;
            } else {
                for (file, op) in results
                    .into_iter()
                    .filter(|(_, (_, _, r))| {
                        matches!(
                            r,
                            TransferResult::Fatal(
                                TransferError::RetryExhausted
                            )
                        )
                    })
                    .map(|(_, (file, op, _))| (file, op))
                {
                    let item = (file, op);
                    let mut queue = download_queue.write().await;
                    if !queue.contains(&item) {
                        queue.push_back(item);
                    }
                }
            }

            Ok::<_, Error>(())
        };

        let results = tokio::join!(requests_task, downloads_task);
        results.0?;
        results.1?;

        Ok({
            let queue = queue.read().await;
            if queue.is_empty() {
                None
            } else {
                Some(())
            }
        })
    }

    async fn run_client_operation(
        request_id: u64,
        file: ExternalFile,
        op: TransferOperation,
        client: C,
        settings: Arc<FileTransferSettings>,
        paths: Arc<Paths>,
        inflight_transfers: Arc<InflightTransfers>,
    ) -> Result<(ExternalFile, TransferOperation, TransferResult)> {
        tracing::debug!(
          request_id = %request_id,
          op = ?op,
          "file_transfers::run",
        );

        let (progress_tx, cancel_tx, cancel_rx) =
            if let TransferOperation::Upload | TransferOperation::Download =
                &op
            {
                let (cancel_tx, cancel_rx) = watch::channel::<()>(());
                let (progress_tx, mut progress_rx): (ProgressChannel, _) =
                    mpsc::channel(16);

                let progress_transfers = inflight_transfers.clone();

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

        let retry = settings.retry.reset();
        let result = match &op {
            TransferOperation::Upload => {
                let operation = operations::UploadOperation::new(
                    client,
                    paths,
                    request_id,
                    inflight_transfers.clone(),
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
                    inflight_transfers.clone(),
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
                    inflight_transfers.clone(),
                    retry,
                );
                operation.run(file).await?
            }
            TransferOperation::Move(dest) => {
                let operation = operations::MoveOperation::new(
                    client,
                    request_id,
                    inflight_transfers.clone(),
                    retry,
                );
                operation.run(file, dest).await?
            }
        };

        {
            tracing::debug!(
                request_id = %request_id,
                "inflight_transfer::remove",
            );

            inflight_transfers.remove_transfer(&request_id).await;
        }

        if let TransferResult::Fatal(reason) = &result {
            // Handle backpressure on notifications
            let notify = InflightNotification::TransferError {
                request_id,
                reason: reason.clone(),
            };

            notify_listeners(notify, &inflight_transfers.notifications).await;
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
