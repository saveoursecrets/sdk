//! Manage pending file transfer operations.
use crate::{
    client::{Error, SyncClient},
    sdk::{
        storage::files::{
            list_external_files, ExternalFile, FileTransfersSet,
            TransferOperation,
        },
        vfs, Paths, Result,
    },
};

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
use tokio::sync::{
    broadcast, mpsc::UnboundedReceiver, oneshot, Mutex, RwLock,
};

/// Channel sender for upload and download progress notifications.
pub type ProgressChannel = broadcast::Sender<(u64, Option<u64>)>;

type PendingOperations = HashMap<ExternalFile, IndexSet<TransferOperation>>;

type InflightTransfersQueue = Arc<RwLock<HashMap<u64, InflightOperation>>>;

/*
/// Channel sender for upload and download progress notifications.
pub type ProgressChannel = broadcast::Sender<(u64, Option<u64>)>;
*/

/// Collection of pending transfers.
pub struct InflightTransfers {
    inflight: InflightTransfersQueue,
    request_id: Arc<Mutex<AtomicU64>>,
    progress: Arc<RwLock<HashMap<u64, Arc<ProgressChannel>>>>,
}

impl InflightTransfers {
    /// Create new pending transfers.
    pub fn new() -> Self {
        Self {
            inflight: Arc::new(RwLock::new(Default::default())),
            request_id: Arc::new(Mutex::new(AtomicU64::new(0))),
            progress: Arc::new(RwLock::new(Default::default())),
        }
    }

    /// Next request id.
    pub async fn request_id(&self) -> u64 {
        let id = self.request_id.lock().await;
        id.fetch_add(1, Ordering::SeqCst)
    }

    /// In flight transfers queue.
    pub fn inflight(&self) -> InflightTransfersQueue {
        Arc::clone(&self.inflight)
    }

    /// Progress channels.
    pub fn progress(
        &self,
    ) -> Arc<RwLock<HashMap<u64, Arc<ProgressChannel>>>> {
        Arc::clone(&self.progress)
    }

    /// Determine if the inflight transfers is empty.
    pub async fn is_empty(&self) -> bool {
        let queue = self.inflight.read().await;
        queue.is_empty()
    }
}

/// In flight transfer operation.
#[derive(Debug, Clone)]
pub struct InflightOperation {
    /// External file information.
    pub file: ExternalFile,
    /// Transfer operation.
    pub operation: TransferOperation,
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
    Fatal,
}

/// Settings for file transfer operations.
pub struct FileTransferSettings {
    /// Number of concurrent transfers.
    pub concurrent_transfers: usize,
    /// Delay in seconds between processing the transfers queue.
    pub delay_seconds: u64,
}

impl Default for FileTransferSettings {
    fn default() -> Self {
        Self {
            concurrent_transfers: 8,
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

                            // Wait for any pending writes to disc
                            // for a graceful shutdown
                            let transfers = queue.read().await;
                            let _ = transfers.path.lock().await;

                            tracing::debug!("file_transfers_shut_down");
                            let _ = shutdown_ack.send(());

                            break;
                        }
                    }
                    _ = futures::future::ready(()).fuse() => {
                        let pending_transfers = {
                            let mut writer = queue.write().await;
                            if let Err(e) = writer.normalize(
                                Arc::clone(&paths),
                            ).await {
                                tracing::error!(error = ?e);
                            }
                            writer.queue.clone()
                        };

                        if !pending_transfers.is_empty() {
                            {
                                // Try to process pending transfers
                                if let Err(e) = Self::try_process_transfers(
                                    Arc::clone(&paths),
                                    &settings,
                                    Arc::clone(&queue),
                                    Arc::clone(&inflight_transfers),
                                    clients.as_slice(),
                                    pending_transfers,
                                ).await {
                                    tracing::warn!(error = ?e);
                                }
                            }
                        }
                    }
                    _ = tokio::time::sleep(
                      Duration::from_secs(settings.delay_seconds)) => {}
                }
            }
        });
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
        let list = pending_transfers.into_iter().collect::<Vec<_>>();
        for files in list.chunks(settings.concurrent_transfers) {
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
                if let TransferOperation::Download = &op {
                    downloads.push(Self::run_client_operation(
                        Arc::clone(&paths),
                        client.clone(),
                        file,
                        op,
                        Arc::clone(&inflight_transfers),
                    ));
                } else {
                    uploads.push(Self::run_client_operation(
                        Arc::clone(&paths),
                        client.clone(),
                        file,
                        op,
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
            if results.into_iter().all(|result| {
                matches!(result, TransferResult::Done | TransferResult::Fatal)
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
            if let TransferResult::Done | TransferResult::Fatal = result {
                let mut writer = queue.write().await;
                writer.transfer_completed(&file, &op).await?;
                return Ok(());
            }
        }

        // Retry the download on the next
        // loop iteration if the download
        // failed on all servers
        Ok(())
    }

    async fn run_client_operation<C>(
        paths: Arc<Paths>,
        client: C,
        file: ExternalFile,
        op: TransferOperation,
        inflight_transfers: Arc<InflightTransfers>,
    ) -> Result<(ExternalFile, TransferOperation, TransferResult)>
    where
        C: SyncClient + Clone + Send + Sync + 'static,
    {
        let (tx, _) = broadcast::channel(32);
        let tx = Arc::new(tx);
        let request_id = inflight_transfers.request_id().await;
        {
            let progress = inflight_transfers.progress();
            let mut progress = progress.write().await;
            progress.insert(request_id, Arc::clone(&tx));
        }
        let inflight_request = InflightOperation {
            file,
            operation: op,
        };

        {
            let mut writer = inflight_transfers.inflight.write().await;
            writer.insert(request_id, inflight_request);
        }

        // tracing::debug!(op = ?op, url = %client.origin().url());

        let result = match &op {
            TransferOperation::Upload => {
                let path = paths.file_location(
                    file.vault_id(),
                    file.secret_id(),
                    file.file_name().to_string(),
                );

                match client.upload_file(&file, &path, tx).await {
                    Ok(status) => Self::is_success(&op, status),
                    Err(e) => Self::is_error(e),
                }
            }
            TransferOperation::Download => {
                // Ensure the parent directory for the download exists
                let parent_path = paths
                    .file_folder_location(file.vault_id())
                    .join(file.secret_id().to_string());

                if !vfs::try_exists(&parent_path).await? {
                    vfs::create_dir_all(&parent_path).await?;
                }

                // Fetch the file
                let path = paths.file_location(
                    file.vault_id(),
                    file.secret_id(),
                    file.file_name().to_string(),
                );
                match client.download_file(&file, &path, tx).await {
                    Ok(status) => Self::is_success(&op, status),
                    Err(e) => Self::is_error(e),
                }
            }
            TransferOperation::Delete => {
                match client.delete_file(&file).await {
                    Ok(status) => Self::is_success(&op, status),
                    Err(e) => Self::is_error(e),
                }
            }
            TransferOperation::Move(dest) => {
                match client.move_file(&file, dest).await {
                    Ok(status) => Self::is_success(&op, status),
                    Err(e) => Self::is_error(e),
                }
            }
        };

        {
            let mut writer = inflight_transfers.inflight.write().await;
            writer.remove(&request_id);

            let progress = inflight_transfers.progress();
            let mut progress = progress.write().await;
            progress.remove(&request_id);
        }

        Ok((file, op, result))
    }

    fn is_success(
        op: &TransferOperation,
        status: StatusCode,
    ) -> TransferResult {
        let ok = match op {
            TransferOperation::Upload => {
                status == StatusCode::OK || status == StatusCode::NOT_MODIFIED
            }
            TransferOperation::Download => status == StatusCode::OK,
            TransferOperation::Delete => {
                status == StatusCode::OK || status == StatusCode::NOT_FOUND
            }
            TransferOperation::Move(_) => status == StatusCode::OK,
        };
        if ok {
            TransferResult::Done
        } else {
            TransferResult::Retry
        }
    }

    fn is_error(error: Error) -> TransferResult {
        tracing::warn!(error = ?error, "transfer_error");
        match error {
            Error::Io(io) => match io.kind() {
                ErrorKind::NotFound => TransferResult::Fatal,
                _ => TransferResult::Retry,
            },
            _ => TransferResult::Retry,
        }
    }
}
