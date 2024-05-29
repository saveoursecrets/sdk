//! Manage pending file transfer operations.
use crate::{
    client::{net::NetworkRetry, Error, Result, SyncClient},
    sdk::{
        storage::files::{ExternalFile, TransferOperation},
        Paths,
    },
};

use futures::FutureExt;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, oneshot, watch, RwLock, Semaphore};

mod inflight;
mod operations;

pub use inflight::{
    InflightNotification, InflightRequest, InflightTransfers,
};
use std::collections::VecDeque;

use super::network_account::FileTransferQueueRequest;

/// Channel for upload and download progress notifications.
pub type ProgressChannel = mpsc::Sender<(u64, Option<u64>)>;

/// Channel used to cancel uploads and downloads.
pub type CancelChannel = watch::Sender<()>;

/// Reason for a transfer error notification.
#[derive(Debug, Clone)]
pub enum TransferError {
    /// Error when network retries are exhausted.
    RetryExhausted,
    /// Error when a file that is the target of
    /// an upload or download is no longer on disc.
    TransferFileMissing,
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
    /// Number of concurrent requests.
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
            concurrent_requests: 8,
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
pub struct FileTransfers {
    settings: Arc<FileTransferSettings>,
    pub(crate) queue:
        Arc<RwLock<VecDeque<(ExternalFile, TransferOperation)>>>,
    pub(crate) inflight: Arc<InflightTransfers>,
}

impl FileTransfers {
    /// Create new file transfers manager.
    pub fn new(settings: FileTransferSettings) -> Self {
        let queue = VecDeque::new();
        let inflight = InflightTransfers::new();

        Self {
            settings: Arc::new(settings),
            queue: Arc::new(RwLock::new(queue)),
            inflight: Arc::new(inflight),
        }
    }

    /// Queue of transfer operations.
    pub fn queue(
        &self,
    ) -> Arc<RwLock<VecDeque<(ExternalFile, TransferOperation)>>> {
        Arc::clone(&self.queue)
    }

    /// Spawn a task to transfer file operations.
    pub fn run<C>(
        &mut self,
        paths: Arc<Paths>,
        clients: Vec<C>,
    ) -> FileTransfersHandle
    where
        C: SyncClient + Clone + Send + Sync + 'static,
    {
        let (handle, mut shutdown_rx, shutdown_tx, mut queue_rx) =
            FileTransfersHandle::new();

        let queue = Arc::clone(&self.queue);
        let inflight = Arc::clone(&self.inflight);
        let settings = Arc::clone(&self.settings);
        let semaphore =
            Arc::new(Semaphore::new(self.settings.concurrent_requests));

        tokio::task::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    signal = shutdown_rx.recv().fuse() => {
                        if signal.is_some() {
                            tracing::debug!("file_transfers_shut_down");
                            let _ = shutdown_tx.send(());
                            break;
                        }
                    }
                    Some(events) = queue_rx.recv() => {
                        {
                            let mut writer = queue.write().await;
                            for event in events {
                                writer.push_front(event);
                            }
                        }

                        Self::try_spawn_tasks(
                            Arc::clone(&paths),
                            Arc::clone(&semaphore),
                            Arc::clone(&queue),
                            Arc::clone(&inflight),
                            Arc::clone(&settings),
                            clients.as_slice(),
                        ).await?;
                    }
                    /*
                    _ = Self::maybe_process_transfers(
                      Arc::clone(&paths),
                      Arc::clone(&settings),
                      Arc::clone(&queue),
                      Arc::clone(&inflight_transfers),
                      clients.as_slice(),
                    ).fuse() => {}
                    */
                }
            }

            Ok::<_, Error>(())
        });

        handle
    }

    async fn try_spawn_tasks<C>(
        paths: Arc<Paths>,
        semaphore: Arc<Semaphore>,
        queue: Arc<RwLock<VecDeque<(ExternalFile, TransferOperation)>>>,
        inflight: Arc<InflightTransfers>,
        settings: Arc<FileTransferSettings>,
        clients: &[C],
    ) -> Result<()>
    where
        C: SyncClient + Clone + Send + Sync + 'static,
    {
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
                        let mut results = Vec::new();
                        for client in clients.to_vec() {
                            let _permit = semaphore.acquire().await.unwrap();
                            let request_id = inflight.request_id().await;

                            tracing::debug!(
                              request_id = %request_id,
                              op = ?op,
                              "file_transfers::run",
                            );

                            let result = Self::run_client_operation(
                                request_id,
                                file,
                                op,
                                client.clone(),
                                Arc::clone(&settings),
                                Arc::clone(&paths),
                                Arc::clone(&inflight),
                            )
                            .await?;

                            let is_done =
                                matches!(&result.2, TransferResult::Done);
                            results.push((request_id, result.2));
                            if is_done {
                                break;
                            }
                        }

                        let done_requests = results
                            .iter()
                            .filter_map(|(id, r)| {
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
                            notify_listeners(notify, &inflight.notifications)
                                .await;
                        } else {
                            println!("Add to back of queue (download)");
                            /*
                            let mut queue = queue.write().await;
                            queue.push_back((file, op));
                            */
                        }
                    }
                    // Other operations must complete on all clients
                    _ => {
                        let mut jhs = Vec::new();
                        for client in clients.to_vec() {
                            let inflight = Arc::clone(&inflight);
                            let settings = Arc::clone(&settings);
                            let paths = Arc::clone(&paths);
                            let permit = Arc::clone(&semaphore);
                            let jh = tokio::task::spawn(async move {
                                let _permit = permit.acquire().await.unwrap();
                                let request_id = inflight.request_id().await;

                                tracing::debug!(
                                  request_id = %request_id,
                                  op = ?op,
                                  "file_transfers::run",
                                );

                                let result = Self::run_client_operation(
                                    request_id,
                                    file,
                                    op,
                                    client.clone(),
                                    Arc::clone(&settings),
                                    Arc::clone(&paths),
                                    Arc::clone(&inflight),
                                )
                                .await?;

                                Ok::<_, Error>((request_id, result.2))
                            });
                            jhs.push(jh);
                        }

                        let mut results = Vec::new();
                        for jh in jhs {
                            let result = jh.await.unwrap()?;
                            results.push(result);
                        }

                        let done = results
                            .iter()
                            .all(|(_, r)| matches!(r, TransferResult::Done));

                        if done {
                            for (request_id, _) in results {
                                let notify =
                                    InflightNotification::TransferDone {
                                        request_id,
                                    };
                                notify_listeners(
                                    notify,
                                    &inflight.notifications,
                                )
                                .await;
                            }
                        } else {
                            println!("Add to back of queue (operation)");

                            /*
                            let mut queue = queue.write().await;
                            queue.push_back((file, op));
                            */
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /*
    /// Try to process the pending transfers list.
    async fn maybe_process_transfers<C>(
        paths: Arc<Paths>,
        settings: Arc<FileTransferSettings>,
        queue: Arc<RwLock<VecDeque<(ExternalFile, TransferOperation)>>>,
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
    */

    /*
    /// Try to process the pending transfers list.
    async fn try_process_transfers<C>(
        paths: Arc<Paths>,
        settings: Arc<FileTransferSettings>,
        queue: Arc<RwLock<VecDeque<(ExternalFile, TransferOperation)>>>,
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
            for (file, op) in list {
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
        queue: Arc<RwLock<VecDeque<(ExternalFile, TransferOperation)>>>,
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
                    results.push((request_id, result));
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
            if results
                .iter()
                .any(|(_, (_, _, r))| matches!(r, TransferResult::Done))
            {

                /*
                for (_, (file, op, _)) in results {
                    let mut writer = queue.write().await;
                    writer.transfer_completed(&file, &op).await?;
                }
                */
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

    async fn process_requests<C>(
        paths: Arc<Paths>,
        concurrency: usize,
        uploads: Vec<(ExternalFile, TransferOperation, Vec<C>)>,
        settings: Arc<FileTransferSettings>,
        queue: Arc<RwLock<VecDeque<(ExternalFile, TransferOperation)>>>,
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
                for (request_id, (file, op, _)) in results {
                    /*
                    let mut writer = queue.write().await;
                    writer.transfer_completed(&file, &op).await?;
                    */

                    let notify =
                        InflightNotification::TransferRemoved { request_id };

                    notify_listeners(
                        notify,
                        &inflight_transfers.notifications,
                    )
                    .await;
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
    */

    async fn run_client_operation<C>(
        request_id: u64,
        file: ExternalFile,
        op: TransferOperation,
        client: C,
        settings: Arc<FileTransferSettings>,
        paths: Arc<Paths>,
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

        let retry = settings.retry.reset();
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
