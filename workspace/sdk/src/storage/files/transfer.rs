//! Manage pending file transfer operations.
use crate::{
    events::FileEvent,
    storage::files::{list_external_files, ExternalFile, FileMutationEvent},
    sync::Client,
    vfs, Paths, Result,
};
use futures::{select, FutureExt};
use http::StatusCode;
use indexmap::IndexSet;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::{collections::HashMap, future::Future, path::PathBuf, sync::Arc};
use tokio::sync::{Mutex, Notify, RwLock};
use tracing::{span, Level};

#[cfg(not(debug_assertions))]
use std::time::Duration;

type TransferQueue = HashMap<ExternalFile, IndexSet<TransferOperation>>;

/// Operations for file transfers.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum TransferOperation {
    /// Upload a file.
    Upload,
    /// Download a file.
    Download,
    /// Delete a file.
    Delete,
    /// Move a file.
    Move(ExternalFile),
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
            let transfers: Self = serde_json::from_slice(&buf)?;
            transfers.queue
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
            entries.remove(op);
            if entries.is_empty() {
                self.queue.remove(file);
            }
        }
        self.save().await
    }

    /// Save the transfer queue to disc.
    async fn save(&self) -> Result<()> {
        let path = self.path.lock().await;
        let buffer = serde_json::to_vec_pretty(self)?;
        vfs::write(&*path, &buffer).await?;
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
        clients: Vec<C>,
        shutdown: Arc<Notify>,
    ) -> ()
    where
        E: std::fmt::Debug + Send + Sync + 'static,
        C: Client<Error = E> + Clone + Send + Sync + 'static,
    {
        tokio::task::spawn(async move {

            loop {
                select! {
                    _ = shutdown.notified().fuse() => {
                        tracing::debug!("shutdown");
                        break;
                    }
                    _ = futures::future::ready(()).fuse() => {
                        let pending_transfers = {
                            let reader = queue.read().await;
                            reader.queue.clone()
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
                                clients.as_slice(),
                                pending_transfers,
                            ).await {
                                tracing::warn!(error = ?e);
                            }
                        }

                        // Pause so we don't overwhelm when re-trying
                        #[cfg(not(debug_assertions))]
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                }
            }
        });
    }

    /// Try to process the pending transfers list.
    async fn try_process_transfers<E, C>(
        paths: Arc<Paths>,
        queue: Arc<RwLock<Transfers>>,
        clients: &[C],
        pending_transfers: TransferQueue,
    ) -> std::result::Result<(), E>
    where
        E: Send + Sync + 'static,
        C: Client<Error = E> + Clone + Send + Sync + 'static,
    {
        // Split uploads and downloads as they require different
        // handling.
        //
        // Uploads must be successful for all remote servers whilst
        // a download only needs to execute successfully against a
        // single server.
        let mut uploads = Vec::new();
        let mut downloads = Vec::new();
        for (file, ops) in pending_transfers {
            for op in ops {
                for client in clients {
                    if let TransferOperation::Download = &op {
                        downloads.push(Self::run_client_operation(
                            Arc::clone(&paths),
                            client.clone(),
                            file,
                            op,
                        ));
                    } else {
                        uploads.push(Self::run_client_operation(
                            Arc::clone(&paths),
                            client.clone(),
                            file,
                            op,
                        ));
                    }
                }
            }
        }

        Self::process_uploads(Arc::clone(&queue), uploads).await?;
        Self::process_downloads(Arc::clone(&queue), downloads).await?;

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
            >,
        >,
    ) -> std::result::Result<(), E>
    where
        E: Send + Sync + 'static,
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
            >,
        >,
    ) -> std::result::Result<(), E>
    where
        E: Send + Sync + 'static,
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
    ) -> std::result::Result<(ExternalFile, TransferOperation, bool), E>
    where
        E: Send + Sync + 'static,
        C: Client<Error = E> + Clone + Send + Sync + 'static,
    {
        let success = match &op {
            TransferOperation::Upload => {
                let path = paths.file_location(
                    file.vault_id(),
                    file.secret_id(),
                    file.file_name().to_string(),
                );
                let status = client.upload_file(&file, &path).await?;
                Self::is_success(&op, status)
            }
            TransferOperation::Download => {
                let path = paths.file_location(
                    file.vault_id(),
                    file.secret_id(),
                    file.file_name().to_string(),
                );
                let status = client.download_file(&file, &path).await?;
                Self::is_success(&op, status)
            }
            TransferOperation::Delete => {
                let status = client.delete_file(&file).await?;
                Self::is_success(&op, status)
            }
            TransferOperation::Move(dest) => {
                let status = client.move_file(&file, dest).await?;
                Self::is_success(&op, status)
            }
        };
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
