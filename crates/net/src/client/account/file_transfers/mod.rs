//! Queue file transfer operations and spawn tasks to
//! perform the file transfer operations.
//!
//! Transfer events are received on a channel
//! and added to a queue of pending operations which are
//! monitored and consumed into inflight transfers.
//!
//! When an error occurs that may be recoverable
//! the queued operation is moved to a failures queue
//! which is polled periodically to see if there are
//! failed transfers that may be retried. If a failed transfer
//! has expired and may be retried it is moved back into the
//! pending transfers queue.
//!
//! Requests are limited to the `concurrent_requests` setting guarded
//! by a semaphore and notifications are sent via [InflightTransfers].
use crate::{
    client::{net::NetworkRetry, CancelReason, Error, Result, SyncClient},
    sdk::{storage::files::ExternalFile, vfs, Paths},
    sync::{FileOperation, Origin, TransferOperation},
};

use futures::FutureExt;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{
    sync::{broadcast, mpsc, oneshot, watch, Mutex, RwLock, Semaphore},
    time,
};

mod inflight;
mod operations;

pub use inflight::{
    InflightNotification, InflightRequest, InflightTransfers,
};
use std::collections::{HashSet, VecDeque};

/// Request to queue a file transfer.
pub type FileTransferQueueRequest = Vec<FileOperation>;

/// Channel for upload and download progress notifications.
pub type ProgressChannel = mpsc::Sender<(u64, Option<u64>)>;

/// Channel used to cancel uploads and downloads.
///
/// The boolean flag indicates whether the cancellation was
/// requested by the user or not.
pub type CancelChannel = watch::Sender<CancelReason>;

/// Reason for a transfer error notification.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum TransferError {
    /// Error when network retries are exhausted.
    RetryExhausted,
    /// Error when a file that is the target of
    /// an upload or download is no longer on disc.
    FileMissing,
    /// Error when the target file for a move operation is missing.
    MovedMissing,
    /// Transfer was canceled.
    Canceled(CancelReason),
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

/// Outcome of an attempted transfer operation.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct TransferOutcome {
    transfer_id: u64,
    request_id: u64,
    file: ExternalFile,
    operation: TransferOperation,
    result: TransferResult,
}

/// Logs a failed transfer attempt.
#[derive(Debug)]
struct TransferFailure {
    time: SystemTime,
    file: ExternalFile,
    operation: TransferOperation,
}

impl From<TransferFailure> for FileOperation {
    fn from(value: TransferFailure) -> Self {
        FileOperation(value.file, value.operation)
    }
}

/// Settings for file transfer operations.
#[derive(Debug, Clone)]
pub struct FileTransferSettings {
    /// Number of concurrent requests.
    pub concurrent_requests: usize,

    /// Duration to poll the failure queue
    /// for expired failures.
    pub failure_interval: Duration,

    /// Duration after which failed transfers are
    /// re-inserted back into the transfers queue.
    pub failure_expiry: Duration,

    /// Settings for network retry.
    ///
    /// Network retry here applies to each individual
    /// file transfer operation.
    pub retry: NetworkRetry,
}

impl Default for FileTransferSettings {
    fn default() -> Self {
        Self {
            concurrent_requests: 4,

            #[cfg(debug_assertions)]
            failure_interval: Duration::from_millis(250),
            #[cfg(not(debug_assertions))]
            failure_interval: Duration::from_millis(30000),

            #[cfg(debug_assertions)]
            failure_expiry: Duration::from_millis(0),
            #[cfg(not(debug_assertions))]
            failure_expiry: Duration::from_secs(180),

            // Disable retry for test specs so they
            // execute fast.
            #[cfg(debug_assertions)]
            retry: NetworkRetry::new(4, 0),
            // In production use default values
            #[cfg(not(debug_assertions))]
            retry: NetworkRetry::default(),
        }
    }
}

impl FileTransferSettings {
    /// Create production file transfer settings.
    pub fn new() -> Self {
        Self {
            concurrent_requests: 4,
            failure_interval: Duration::from_millis(30000),
            failure_expiry: Duration::from_secs(180),
            retry: NetworkRetry::default(),
        }
    }
}

/// Handle that can be used to shutdown the file transfers event
/// loop and send events to the queue.
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
    queue: Arc<RwLock<VecDeque<FileOperation>>>,
    failures: Arc<Mutex<VecDeque<TransferFailure>>>,
    pub(super) inflight: Arc<InflightTransfers>,
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
            failures: Arc::new(Mutex::new(Default::default())),
            inflight: Arc::new(inflight),
        }
    }

    /// Add a client target for file transfer operations.
    pub(super) async fn add_client(&self, client: C) {
        let mut writer = self.clients.lock().await;
        writer.push(client);
    }

    /// Remove a client target for file transfer operations.
    pub(super) async fn remove_client(&self, client: &C) {
        let mut writer = self.clients.lock().await;
        if let Some(pos) = writer.iter().position(|c| c == client) {
            writer.remove(pos);
        }
    }

    /// Spawn a task to transfer file operations.
    pub(super) fn run(&mut self, paths: Arc<Paths>) -> FileTransfersHandle {
        let (handle, mut shutdown_rx, shutdown_tx, mut queue_rx) =
            FileTransfersHandle::new();

        let queue_tx = handle.queue_tx.clone();

        let queue_drained = Arc::new(Mutex::new(false));

        let clients = self.clients.clone();
        let queue = self.queue.clone();
        let inflight = self.inflight.clone();
        let cancel_inflight = self.inflight.clone();
        let settings = self.settings.clone();
        let failures = self.failures.clone();
        let semaphore =
            Arc::new(Semaphore::new(self.settings.concurrent_requests));

        let failure_expiry = settings.failure_expiry;
        let mut interval = time::interval(settings.failure_interval);

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
                            cancel_inflight.cancel_all(CancelReason::Shutdown).await;

                            let _ = shutdown_tx.send(());
                            tracing::debug!("file_transfers::shut_down");

                            break;
                        }
                    }
                    _ = interval.tick() => {
                        let mut failures = failures.lock().await;
                        let mut items = Vec::new();
                        while let Some(failure) = failures.pop_back() {
                            if let Ok(elapsed) = failure.time.elapsed() {
                                if elapsed >= failure_expiry {
                                    items.push(failure.into());
                                } else {
                                    failures.push_front(failure);
                                }
                            }
                        }

                        if !items.is_empty() {
                            if let Err(error) = queue_tx.send(items).await {
                                tracing::error!(error = ?error, "file_transfers::reinsert");
                            }
                        }
                    }
                    Some(events) = queue_rx.recv() => {
                        // println!("queue events: {}", events.len());

                        let num_clients = {
                            let reader = clients.lock().await;
                            reader.len()
                        };

                        // If we don't have any clients no point
                        // queuing anything
                        if num_clients == 0 {
                            continue;
                        }

                        let num_queued = {

                            // Normalize for delete and move events
                            // that should cancel any existing upload
                            // or download operations
                            for event in &events {
                                normalize(
                                    &event.0,
                                    &event.1,
                                    queue.clone(),
                                    failures.clone(),
                                    inflight.clone(),
                                ).await;
                            }

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

                        tracing::debug!(
                            num_clients = %num_clients,
                            num_queued = %num_queued,
                            is_running = %is_running,
                            "file_transfers::event");

                        // Guard to ensure there is only one spawned
                        // task consuming the queue at a time
                        if num_queued > 0 && !is_running {
                          // Clone of the current client list which
                          // will remain fixed until the current queue
                          // is completely drained
                          let clients = {
                            let reader = clients.lock().await;
                            reader.iter().cloned().collect::<Vec<_>>()
                          };

                          if !clients.is_empty() {
                              {
                                let mut writer = queue_drained.lock().await;
                                *writer = true;
                              }

                              let semaphore = semaphore.clone();
                              let queue = queue.clone();
                              let failures = failures.clone();
                              let inflight = inflight.clone();
                              let settings = settings.clone();
                              let paths = paths.clone();
                              let drained = queue_drained.clone();

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
                                    failures.clone(),
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
        queue: Arc<RwLock<VecDeque<FileOperation>>>,
        failures: Arc<Mutex<VecDeque<TransferFailure>>>,
        inflight: Arc<InflightTransfers>,
        settings: Arc<FileTransferSettings>,
        clients: Vec<C>,
    ) -> Result<()> {
        let mut remaining = Self::consume_queue(
            paths.clone(),
            semaphore.clone(),
            queue.clone(),
            failures.clone(),
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
                failures.clone(),
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
        queue: Arc<RwLock<VecDeque<FileOperation>>>,
        failures: Arc<Mutex<VecDeque<TransferFailure>>>,
        inflight: Arc<InflightTransfers>,
        settings: Arc<FileTransferSettings>,
        clients: &[C],
    ) -> Result<Option<()>> {
        let mut requests = Vec::new();
        let mut downloads = Vec::new();

        loop {
            // Concurrency limit reached
            if semaphore.available_permits() == 0 {
                break;
            }

            let item = {
                let mut queue = queue.write().await;
                queue.pop_back()
            };

            // No more items in the queue
            if item.is_none() {
                break;
            }

            let FileOperation(file, op) = item.unwrap();

            // println!("process: {:#?}", op);
            tracing::debug!(
              file = ?file,
              op = ?op,
              "file_transfers::queue",
            );

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
                            let request_id = inflight.request_id();

                            let outcome = Self::run_client_operation(
                                request_id,
                                file,
                                op,
                                client.clone(),
                                settings.clone(),
                                paths.clone(),
                                inflight.clone(),
                            )
                            .await?;

                            let is_done = matches!(
                                &outcome.result,
                                TransferResult::Done
                            );
                            results.push(outcome);
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
                            let request_id = inflight.request_id();
                            let outcome = Self::run_client_operation(
                                request_id,
                                file,
                                op,
                                client.clone(),
                                settings.clone(),
                                paths.clone(),
                                inflight.clone(),
                            )
                            .await?;

                            Ok::<_, Error>(outcome)
                        });
                        requests.push(jh);
                    }
                }
            }
        }

        let request_paths = paths.clone();
        let request_queue = queue.clone();
        let download_inflight = inflight.clone();
        let download_failures = failures.clone();

        let requests_task = async move {
            let mut results = Vec::new();
            for jh in requests {
                let outcome = jh.await.unwrap()?;
                if let TransferResult::Done = &outcome.result {
                    let notify = InflightNotification::TransferDone {
                        transfer_id: outcome.transfer_id,
                        request_id: outcome.request_id,
                    };
                    notify_listeners(notify, &inflight.notifications).await;
                }

                results.push(outcome);
            }

            let done = results
                .iter()
                .all(|o| matches!(o.result, TransferResult::Done));

            if !done {
                // println!("result: {:#?}", results);

                // If we attempt a move but the source file
                // of the move is missing on the target server
                // and we have the destination locally
                // on disc then we mutate it into an upload operation
                let moved_missing = results
                    .iter()
                    .filter(|o| {
                        matches!(
                            o.result,
                            TransferResult::Fatal(
                                TransferError::MovedMissing
                            )
                        )
                    })
                    .cloned()
                    .collect::<HashSet<_>>();
                for outcome in moved_missing {
                    if let TransferOperation::Move(dest) = &outcome.operation
                    {
                        let path = request_paths.file_location(
                            dest.vault_id(),
                            dest.secret_id(),
                            dest.file_name().to_string(),
                        );

                        if vfs::try_exists(path).await? {
                            let item = FileOperation(
                                dest.clone(),
                                TransferOperation::Upload,
                            );
                            let mut queue = request_queue.write().await;
                            if !queue.contains(&item) {
                                queue.push_back(item);
                            }
                        }
                    }
                }

                for (file, op) in results
                    .into_iter()
                    .filter(|o| {
                        matches!(
                            o.result,
                            TransferResult::Fatal(
                                TransferError::RetryExhausted
                            )
                        )
                    })
                    .map(|o| (o.file, o.operation))
                {
                    let item = TransferFailure {
                        time: SystemTime::now(),
                        file,
                        operation: op,
                    };
                    let mut failures = failures.lock().await;
                    failures.push_front(item);
                }
            }

            Ok::<_, Error>(())
        };

        let downloads_task = async move {
            let mut results = Vec::new();
            for jh in downloads {
                let download_outcomes = jh.await.unwrap()?;
                let done_requests = download_outcomes
                    .iter()
                    .filter(|o| matches!(o.result, TransferResult::Done))
                    .collect::<Vec<_>>();

                for outcome in done_requests {
                    if let TransferResult::Done = &outcome.result {
                        let notify = InflightNotification::TransferDone {
                            transfer_id: outcome.transfer_id,
                            request_id: outcome.request_id,
                        };
                        notify_listeners(
                            notify,
                            &download_inflight.notifications,
                        )
                        .await;
                    }
                }

                results.push(download_outcomes);
            }

            let results = results.into_iter().flatten().collect::<Vec<_>>();

            for (file, operation) in results
                .into_iter()
                .filter(|o| {
                    matches!(
                        o.result,
                        TransferResult::Fatal(TransferError::RetryExhausted)
                    )
                })
                .map(|o| (o.file, o.operation))
            {
                let item = TransferFailure {
                    time: SystemTime::now(),
                    file,
                    operation,
                };
                let mut failures = download_failures.lock().await;
                failures.push_front(item);
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
    ) -> Result<TransferOutcome> {
        tracing::debug!(
          request_id = %request_id,
          op = ?op,
          "file_transfers::run",
        );

        let transfer_id = compute_transfer_id(&file, &op, client.origin());

        let (cancel_tx, cancel_rx) =
            watch::channel::<CancelReason>(Default::default());
        let progress_tx = match &op {
            TransferOperation::Upload | TransferOperation::Download => {
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
                            transfer_id,
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

                Some(progress_tx)
            }
            _ => None,
        };

        {
            let request = InflightRequest {
                origin: client.origin().clone(),
                file,
                operation: op,
                cancel: cancel_tx.clone(),
            };

            tracing::debug!(
                request_id = %request_id,
                "inflight_transfer::insert",
            );

            let notify = InflightNotification::TransferAdded {
                transfer_id,
                request_id,
                origin: request.origin.clone(),
                file: request.file.clone(),
                operation: request.operation.clone(),
            };

            inflight_transfers
                .insert_transfer(request_id, request)
                .await;

            notify_listeners(notify, &inflight_transfers.notifications).await;
        };

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
                    transfer_id,
                    request_id,
                    inflight_transfers.clone(),
                    retry,
                    cancel_tx,
                );
                operation
                    .run(&file, progress_tx.unwrap(), cancel_rx)
                    .await?
            }
            TransferOperation::Download => {
                let operation = operations::DownloadOperation::new(
                    client,
                    paths,
                    transfer_id,
                    request_id,
                    inflight_transfers.clone(),
                    retry,
                    cancel_tx,
                );
                operation
                    .run(&file, progress_tx.unwrap(), cancel_rx)
                    .await?
            }
            TransferOperation::Delete => {
                let operation = operations::DeleteOperation::new(
                    client,
                    transfer_id,
                    request_id,
                    inflight_transfers.clone(),
                    retry,
                    cancel_tx,
                );
                operation.run(&file).await?
            }
            TransferOperation::Move(dest) => {
                let operation = operations::MoveOperation::new(
                    client,
                    transfer_id,
                    request_id,
                    inflight_transfers.clone(),
                    retry,
                    cancel_tx,
                );
                operation.run(&file, dest).await?
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
            let notify = InflightNotification::TransferError {
                transfer_id,
                request_id,
                reason: reason.clone(),
            };
            notify_listeners(notify, &inflight_transfers.notifications).await;
        }

        Ok(TransferOutcome {
            transfer_id,
            request_id,
            file,
            operation: op,
            result,
        })
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

/// Compute an id for the transfer.
///
/// Transfer identifiers are stable across requests
/// so callers can use this to identify transfers that
/// may already have requests running.
fn compute_transfer_id(
    file: &ExternalFile,
    operation: &TransferOperation,
    origin: &Origin,
) -> u64 {
    let mut hasher = DefaultHasher::new();
    file.hash(&mut hasher);
    operation.hash(&mut hasher);
    origin.hash(&mut hasher);
    hasher.finish()
}

async fn normalize(
    file: &ExternalFile,
    operation: &TransferOperation,
    queue: Arc<RwLock<VecDeque<FileOperation>>>,
    failures: Arc<Mutex<VecDeque<TransferFailure>>>,
    inflight: Arc<InflightTransfers>,
) {
    match operation {
        TransferOperation::Delete | TransferOperation::Move(_) => {
            tracing::debug!(
              op = ?operation,
              "file_transfers::normalize_operation",
            );

            // Remove from the pending queue
            let mut queue = queue.write().await;
            queue.retain(|item| {
                let is_transfer_op = matches!(
                    item.1,
                    TransferOperation::Upload | TransferOperation::Download
                );
                if &item.0 == file && is_transfer_op {
                    false
                } else {
                    true
                }
            });

            // Remove from the failures queue
            let mut failures = failures.lock().await;
            failures.retain(|failure| {
                let is_transfer_op = matches!(
                    failure.operation,
                    TransferOperation::Upload | TransferOperation::Download
                );
                if &failure.file == file && is_transfer_op {
                    false
                } else {
                    true
                }
            });

            // Notmalize inflight transfers which will cancel
            // any existing uploads/downloads
            inflight.cancel_active_transfers(file).await;
        }
        _ => {}
    }
}
