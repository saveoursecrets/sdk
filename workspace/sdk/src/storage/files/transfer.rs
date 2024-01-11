//! Manage pending file transfer operations.
use crate::{
    events::FileEvent,
    storage::files::{list_external_files, ExternalFile, FileMutationEvent},
    vfs, Paths, Result,
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::{collections::HashMap, path::PathBuf};
use tokio::sync::Mutex;

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
#[derive(Serialize, Deserialize)]
pub struct Transfers {
    #[serde(skip)]
    path: Mutex<PathBuf>,
    #[serde_as(as = "HashMap<DisplayFromStr, _>")]
    #[serde(flatten)]
    queue: HashMap<ExternalFile, Vec<TransferOperation>>,
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
                cache.queue.insert(file, vec![TransferOperation::Upload]);
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

    /// Add file transfer operations to the queue.
    pub async fn queue_transfers(
        &mut self,
        ops: HashMap<ExternalFile, Vec<TransferOperation>>,
    ) -> Result<()> {
        for (file, mut operations) in ops {
            let entries = self.queue.entry(file).or_insert(vec![]);
            entries.append(&mut operations);
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
            if let Some(position) = entries.iter().position(|o| o == op) {
                entries.remove(position);
            }
            if entries.is_empty() {
                self.queue.remove(file);
            }
        }
        self.save().await
    }

    async fn save(&self) -> Result<()> {
        let path = self.path.lock().await;
        let buffer = serde_json::to_vec_pretty(self)?;
        vfs::write(&*path, &buffer).await?;
        Ok(())
    }
}
