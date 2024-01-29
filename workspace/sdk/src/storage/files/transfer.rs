//! Manage pending file transfer operations.
use crate::{
    events::FileEvent,
    storage::files::{list_external_files, ExternalFile, FileMutationEvent},
    sync::SyncClient,
    vfs, Paths, Result,
};
use futures::{select, FutureExt};
use http::StatusCode;
use indexmap::IndexSet;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
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
use tracing::{span, Level};

type TransferQueue = HashMap<ExternalFile, IndexSet<TransferOperation>>;

type InflightTransfersQueue = Arc<RwLock<HashMap<u64, InflightOperation>>>;

/// Channel sender for upload and download progress notifications.
pub type ProgressChannel = broadcast::Sender<(u64, Option<u64>)>;

/// Set of files built from the state on disc.
#[derive(Debug, Default)]
pub struct FileSet(pub HashSet<ExternalFile>);

/// Sets of files that should be uploaded and
/// downloaded from a remote server.
#[derive(Debug, Default)]
pub struct FileTransfersSet {
    /// Files that exist on local but not on remote.
    pub uploads: FileSet,
    /// Files that exist on remote but not on local.
    pub downloads: FileSet,
}

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

/// Operations for file transfers.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde_as]
#[serde(rename_all = "lowercase")]
pub enum TransferOperation {
    /// Upload a file.
    Upload,
    /// Download a file.
    Download,
    /// Delete a file.
    Delete,
    /// Move a file.
    Move(#[serde_as(as = "DisplayFromStr")] ExternalFile),
}

impl From<&FileMutationEvent> for (ExternalFile, TransferOperation) {
    fn from(value: &FileMutationEvent) -> Self {
        match value {
            FileMutationEvent::Create { event, .. } => event.into(),
            FileMutationEvent::Move(event) => event.into(),
            FileMutationEvent::Delete(event) => event.into(),
        }
    }
}

impl From<&FileEvent> for (ExternalFile, TransferOperation) {
    fn from(value: &FileEvent) -> Self {
        match value {
            FileEvent::CreateFile(vault_id, secret_id, file_name) => (
                ExternalFile::new(*vault_id, *secret_id, *file_name),
                TransferOperation::Upload,
            ),
            FileEvent::DeleteFile(vault_id, secret_id, file_name) => (
                ExternalFile::new(*vault_id, *secret_id, *file_name),
                TransferOperation::Delete,
            ),
            FileEvent::MoveFile { name, from, dest } => (
                ExternalFile::new(from.0, from.1, *name),
                TransferOperation::Move(ExternalFile::new(
                    dest.0, dest.1, *name,
                )),
            ),
            _ => panic!("attempt to convert noop file event"),
        }
    }
}

/// Queue of transfer operations.
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct Transfers {
    #[serde(skip)]
    path: Mutex<PathBuf>,
    #[serde_as(as = "HashMap<DisplayFromStr, _>")]
    #[serde(flatten)]
    queue: TransferQueue,
}

impl Transfers {
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
    pub fn queue(&self) -> &TransferQueue {
        &self.queue
    }

    /// Add file transfer operations to the queue.
    pub async fn queue_transfers(
        &mut self,
        ops: TransferQueue,
    ) -> Result<()> {
        for (file, mut operations) in ops {
            let entries = self.queue.entry(file).or_insert(IndexSet::new());
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
                    (ops.len() == 1, ops.get(0))
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
                ) = (ops.len() == 2, ops.get(0), ops.get(1))
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

/// Transfers files to multiple clients.
///
/// Reads operations from the queue, executes them on
/// the list of clients and removes from the queue only
/// when each operation has been completed on every client.
pub struct FileTransfers;

impl FileTransfers {
    /// Spawn a task to transfer file operations.
    pub fn start<E, C>(
        paths: Arc<Paths>,
        queue: Arc<RwLock<Transfers>>,
        inflight_transfers: Arc<InflightTransfers>,
        clients: Vec<C>,
        mut shutdown: UnboundedReceiver<()>,
        shutdown_ack: oneshot::Sender<()>,
    ) -> ()
    where
        E: std::fmt::Debug + Send + Sync + 'static,
        C: SyncClient<Error = E> + Clone + Send + Sync + 'static,
    {
        tokio::task::spawn(async move {
            loop {
                select! {
                    signal = shutdown.recv().fuse() => {
                        if signal.is_some() {
                            let span = span!(Level::DEBUG, "file_transfers");
                            let _enter = span.enter();
                            tracing::debug!("shutdown");

                            // Wait for any pending writes to disc
                            // for a graceful shutdown
                            let transfers = queue.read().await;
                            let _ = transfers.path.lock().await;

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

                        // Try again later
                        if pending_transfers.is_empty() {
                            #[cfg(not(debug_assertions))]
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            continue;
                        }

                        {
                            let span = span!(Level::DEBUG, "file_transfers");
                            let _enter = span.enter();

                            // Try to process pending transfers
                            if let Err(e) = Self::try_process_transfers(
                                Arc::clone(&paths),
                                Arc::clone(&queue),
                                Arc::clone(&inflight_transfers),
                                clients.as_slice(),
                                pending_transfers,
                            ).await {
                                tracing::warn!(error = ?e);
                            }
                        }

                        // Pause so we don't overwhelm when re-trying
                        #[cfg(not(debug_assertions))]
                        tokio::time::sleep(Duration::from_secs(30)).await;

                        #[cfg(debug_assertions)]
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }

            let _ = shutdown_ack.send(());
        });
    }

    /// Try to process the pending transfers list.
    async fn try_process_transfers<E, C>(
        paths: Arc<Paths>,
        queue: Arc<RwLock<Transfers>>,
        inflight_transfers: Arc<InflightTransfers>,
        clients: &[C],
        pending_transfers: TransferQueue,
    ) -> std::result::Result<(), E>
    where
        E: std::fmt::Debug + Send + Sync + 'static,
        C: SyncClient<Error = E> + Clone + Send + Sync + 'static,
    {
        for (file, ops) in pending_transfers {
            Self::process_operations(
                file,
                ops,
                Arc::clone(&paths),
                Arc::clone(&queue),
                Arc::clone(&inflight_transfers),
                clients,
            )
            .await?;
        }

        Ok(())
    }

    async fn process_operations<E, C>(
        file: ExternalFile,
        operations: IndexSet<TransferOperation>,
        paths: Arc<Paths>,
        queue: Arc<RwLock<Transfers>>,
        inflight_transfers: Arc<InflightTransfers>,
        clients: &[C],
    ) -> std::result::Result<(), E>
    where
        E: std::fmt::Debug + Send + Sync + 'static,
        C: SyncClient<Error = E> + Clone + Send + Sync + 'static,
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

            for client in clients {
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
                Box<
                    dyn Future<Output = std::result::Result<(), E>>
                        + Send
                        + 'static,
                >,
            > = Box::pin(Self::process_uploads(Arc::clone(&queue), uploads));
            let down: Pin<
                Box<
                    dyn Future<Output = std::result::Result<(), E>>
                        + Send
                        + 'static,
                >,
            > = Box::pin(Self::process_downloads(
                Arc::clone(&queue),
                downloads,
            ));

            let transfers = vec![up, down];
            futures::future::try_join_all(transfers).await?;
        }

        Ok(())
    }

    async fn process_uploads<E>(
        queue: Arc<RwLock<Transfers>>,
        uploads: Vec<
            impl Future<
                    Output = std::result::Result<
                        (ExternalFile, TransferOperation, bool),
                        E,
                    >,
                > + Send
                + 'static,
        >,
    ) -> std::result::Result<(), E>
    where
        E: std::fmt::Debug + Send + Sync + 'static,
    {
        // Execute the client requests
        let results = futures::future::try_join_all(uploads).await?;

        // Collate results that completed for all clients
        let mut collated = HashMap::new();
        for (file, op, done) in results {
            let entry = collated.entry((file, op)).or_insert(done);
            *entry = *entry && done;
        }

        // Mark transfers that were successful for all clients
        // as completed, removing them from the queue
        for ((file, op), done) in collated {
            if done {
                let mut writer = queue.write().await;
                if let Err(e) = writer.transfer_completed(&file, &op).await {
                    tracing::error!(error = ?e);
                    panic!("failed to remove pending transfer");
                }
            }
        }

        Ok(())
    }

    async fn process_downloads<E>(
        queue: Arc<RwLock<Transfers>>,
        downloads: Vec<
            impl Future<
                    Output = std::result::Result<
                        (ExternalFile, TransferOperation, bool),
                        E,
                    >,
                > + Send
                + 'static,
        >,
    ) -> std::result::Result<(), E>
    where
        E: std::fmt::Debug + Send + Sync + 'static,
    {
        for fut in downloads {
            let (file, op, done) = fut.await?;
            if done {
                let mut writer = queue.write().await;
                if let Err(e) = writer.transfer_completed(&file, &op).await {
                    tracing::error!(error = ?e);
                    panic!("failed to remove pending transfer");
                }
                return Ok(());
            }
        }

        // Retry the download on the next
        // loop iteration if the download
        // failed on all servers
        Ok(())
    }

    async fn run_client_operation<E, C>(
        paths: Arc<Paths>,
        client: C,
        file: ExternalFile,
        op: TransferOperation,
        inflight_transfers: Arc<InflightTransfers>,
    ) -> std::result::Result<(ExternalFile, TransferOperation, bool), E>
    where
        E: std::fmt::Debug + Send + Sync + 'static,
        C: SyncClient<Error = E> + Clone + Send + Sync + 'static,
    {
        let (tx, _) = broadcast::channel(512);
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

        tracing::debug!(op = ?op, url = %client.origin().url());
        //println!("{:#?}", op);

        let success = match &op {
            TransferOperation::Upload => {
                let path = paths.file_location(
                    file.vault_id(),
                    file.secret_id(),
                    file.file_name().to_string(),
                );

                match client.upload_file(&file, &path, tx).await {
                    Ok(status) => Self::is_success(&op, status),
                    Err(e) => {
                        //eprintln!("UPLOAD FAIL {:#?}", e);
                        tracing::warn!(error = ?e);
                        false
                    }
                }
            }
            TransferOperation::Download => {
                // Ensure the parent directory for the download exists
                let parent_path = paths
                    .file_folder_location(file.vault_id())
                    .join(file.secret_id().to_string());

                // TODO: fix type declarations so we can do
                // TODO: error conversion
                if vfs::try_exists(&parent_path).await.is_ok() {
                    if let Err(e) = vfs::create_dir_all(&parent_path).await {
                        tracing::error!(error = ?e);
                    }
                }

                // Fetch the file
                let path = paths.file_location(
                    file.vault_id(),
                    file.secret_id(),
                    file.file_name().to_string(),
                );
                match client.download_file(&file, &path, tx).await {
                    Ok(status) => Self::is_success(&op, status),
                    Err(e) => {
                        tracing::warn!(error = ?e);
                        false
                    }
                }
            }
            TransferOperation::Delete => {
                match client.delete_file(&file).await {
                    Ok(status) => Self::is_success(&op, status),
                    Err(e) => {
                        tracing::warn!(error = ?e);
                        false
                    }
                }
            }
            TransferOperation::Move(dest) => {
                match client.move_file(&file, dest).await {
                    Ok(status) => Self::is_success(&op, status),
                    Err(e) => {
                        tracing::warn!(error = ?e);
                        false
                    }
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

        Ok((file, op, success))
    }

    fn is_success(op: &TransferOperation, status: StatusCode) -> bool {
        match op {
            TransferOperation::Upload => {
                status == StatusCode::OK || status == StatusCode::NOT_MODIFIED
            }
            TransferOperation::Download => status == StatusCode::OK,
            TransferOperation::Delete => {
                status == StatusCode::OK || status == StatusCode::NOT_FOUND
            }
            TransferOperation::Move(_) => status == StatusCode::OK,
        }
    }
}
