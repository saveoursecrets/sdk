use crate::{
    commit::{CommitHash, CommitProof},
    events::{AccountEvent, EventRecord, WriteEvent},
    Result,
};
use binary_stream::futures::{Decodable, Encodable};
use std::marker::PhantomData;

use crate::events::DeviceEvent;

#[cfg(feature = "files")]
use crate::events::FileEvent;

/// Patch of account events.
pub type AccountPatch = Patch<AccountEvent>;

/// Patch of folder events.
pub type FolderPatch = Patch<WriteEvent>;

/// Patch of device events.
pub type DevicePatch = Patch<DeviceEvent>;

/// Patch of file events.
#[cfg(feature = "files")]
pub type FilePatch = Patch<FileEvent>;

/// Patch wraps a changeset of events to be sent across the network.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Patch<T>(Vec<EventRecord>, PhantomData<T>);

impl<T> Patch<T> {
    /// Create a new patch from event records.
    pub fn new(records: Vec<EventRecord>) -> Self {
        Self(records, PhantomData)
    }

    /// Number of events in this patch.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this patch is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterator of the event records.
    pub fn iter(&self) -> impl Iterator<Item = &EventRecord> {
        self.0.iter()
    }

    /// Mutable event records.
    pub fn records(&self) -> &[EventRecord] {
        self.0.as_slice()
    }

    /// Decode this patch into the events.
    pub async fn into_events<E: Default + Decodable + Encodable>(
        &self,
    ) -> Result<Vec<E>> {
        let mut events = Vec::with_capacity(self.0.len());
        for record in &self.0 {
            events.push(record.decode_event::<E>().await?);
        }
        Ok(events)
    }
}

impl<T> From<Patch<T>> for Vec<EventRecord> {
    fn from(value: Patch<T>) -> Self {
        value.0
    }
}

/// Result of a checked patch on an event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckedPatch {
    /// Patch was applied.
    Success(CommitProof),
    /// Patch conflict.
    Conflict {
        /// Head of the event log.
        head: CommitProof,
        /// If the checked proof is contained
        /// in the event log.
        contains: Option<CommitProof>,
    },
}

/// Diff between local and remote.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Diff<T> {
    /// Contents of the patch.
    pub patch: Patch<T>,
    /// Checkpoint for the diff patch.
    ///
    /// For checked patches this must match the proof
    /// of HEAD before the patch was created.
    ///
    /// For unchecked force merges this checkpoint
    /// references the commit proof of HEAD after
    /// applying the patch.
    pub checkpoint: CommitProof,
    /// Last commit hash before the patch was created.
    ///
    /// This can be used to determine if the patch is to
    /// be used to initialize a new set of events when
    /// no last commit is available.
    ///
    /// For example, for file event logs which are
    /// lazily instantiated once external files are created.
    pub last_commit: Option<CommitHash>,
}

impl<T> Diff<T> {
    /// Create a diff.
    pub fn new(
        patch: Patch<T>,
        checkpoint: CommitProof,
        last_commit: Option<CommitHash>,
    ) -> Self {
        Self {
            patch,
            checkpoint,
            last_commit,
        }
    }
}

/// Diff between account events logs.
pub type AccountDiff = Diff<AccountEvent>;

/// Diff between device events logs.
pub type DeviceDiff = Diff<DeviceEvent>;

/// Diff between file events logs.
#[cfg(feature = "files")]
pub type FileDiff = Diff<FileEvent>;

/// Diff between folder events logs.
pub type FolderDiff = Diff<WriteEvent>;
