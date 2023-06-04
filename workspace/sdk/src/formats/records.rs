//! File format iterators.
use std::ops::Range;

use crate::Timestamp;
use binary_stream::futures::Decode;

/// Trait for types yielded by the file iterator.
pub trait FileItem: Default + std::fmt::Debug + Decode {
    /// Get the byte offset for the record.
    fn offset(&self) -> &Range<u64>;

    /// Get the range for the record value.
    fn value(&self) -> &Range<u64>;

    /// Set the byte offset for the record.
    fn set_offset(&mut self, offset: Range<u64>);

    /// Set the range for the record value.
    fn set_value(&mut self, value: Range<u64>);
}

/// Generic reference to a row in a file.
#[derive(Default, Debug)]
pub struct FileRecord {
    /// Byte offset for the record.
    offset: Range<u64>,
    /// The byte range for the value.
    value: Range<u64>,
}

impl FileItem for FileRecord {
    fn offset(&self) -> &Range<u64> {
        &self.offset
    }

    fn value(&self) -> &Range<u64> {
        &self.value
    }

    fn set_offset(&mut self, offset: Range<u64>) {
        self.offset = offset;
    }

    fn set_value(&mut self, value: Range<u64>) {
        self.value = value;
    }
}

/// Reference to a row in a vault.
#[derive(Default, Debug)]
pub struct VaultRecord {
    /// Byte offset for the record.
    offset: Range<u64>,
    /// The byte range for the value.
    value: Range<u64>,
    /// The identifier for the secret.
    pub(crate) id: [u8; 16],
    /// The commit hash for the secret.
    pub(crate) commit: [u8; 32],
}

impl FileItem for VaultRecord {
    fn offset(&self) -> &Range<u64> {
        &self.offset
    }

    fn value(&self) -> &Range<u64> {
        &self.value
    }

    fn set_offset(&mut self, offset: Range<u64>) {
        self.offset = offset;
    }

    fn set_value(&mut self, value: Range<u64>) {
        self.value = value;
    }
}

impl VaultRecord {
    /// Get the identifier for the secret.
    pub fn id(&self) -> [u8; 16] {
        self.id
    }

    /// Get the commit hash for the secret.
    pub fn commit(&self) -> [u8; 32] {
        self.commit
    }
}

/// Reference to a row in the write ahead log.
#[derive(Default, Debug, Eq)]
pub struct EventLogFileRecord {
    /// Byte offset for the record.
    offset: Range<u64>,
    /// The byte range for the value.
    value: Range<u64>,
    /// The time the row was created.
    pub(crate) time: Timestamp,
    /// The commit hash for the previous row.
    pub(crate) last_commit: [u8; 32],
    /// The commit hash for the value.
    pub(crate) commit: [u8; 32],
}

impl EventLogFileRecord {
    /// Commit hash for this row.
    pub fn commit(&self) -> [u8; 32] {
        self.commit
    }

    /// Commit hash for the previous row.
    pub fn last_commit(&self) -> [u8; 32] {
        self.last_commit
    }

    /// Time the row was appended.
    pub fn time(&self) -> &Timestamp {
        &self.time
    }
}

impl PartialEq for EventLogFileRecord {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time
            && self.commit == other.commit
            && self.last_commit == other.last_commit
    }
}

impl FileItem for EventLogFileRecord {
    fn offset(&self) -> &Range<u64> {
        &self.offset
    }

    fn value(&self) -> &Range<u64> {
        &self.value
    }

    fn set_offset(&mut self, offset: Range<u64>) {
        self.offset = offset;
    }

    fn set_value(&mut self, value: Range<u64>) {
        self.value = value;
    }
}
