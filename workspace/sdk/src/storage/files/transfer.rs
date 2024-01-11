//! Manage pending file transfer operations.
use crate::storage::files::ExternalFile;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

/// Queue of transfer operations.
#[derive(Default, Serialize, Deserialize)]
pub struct Transfers {
    queue: HashMap<ExternalFile, Vec<TransferOperation>>,
}

impl Transfers {
    /// Add a file transfer operation to the queue.
    pub fn queue_transfer(
        &mut self,
        file: ExternalFile,
        op: TransferOperation,
    ) {
        let entries = self.queue.entry(file).or_insert(vec![]);
        entries.push(op);
    }
    
    /// Mark a transfer operation as completed.
    pub fn transfer_completed(
        &mut self,
        file: &ExternalFile,
        op: &TransferOperation,
    ) {
        if let Some(entries) = self.queue.get_mut(file) {
            if let Some(position) = entries.iter().position(|o| o == op) {
                entries.remove(position);
            }
            if entries.is_empty() {
                self.queue.remove(file);
            }
        }
    }
}
