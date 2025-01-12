use crate::{
    commit::{CommitHash, CommitProof, CommitTree},
    events::{
        patch::{CheckedPatch, Diff, Patch},
        EventRecord,
    },
    Error,
};
use async_trait::async_trait;
use binary_stream::futures::{Decodable, Encodable};
use futures::stream::BoxStream;

/// Event log iterator, stream and diff support.
#[async_trait]
pub trait EventLog<E>: Send + Sync
where
    E: Default + Encodable + Decodable + Send + Sync + 'static,
{
    /// Error type.
    type Error: std::error::Error + std::fmt::Debug + From<Error>;

    /// Commit tree contains the in-memory merkle tree.
    fn tree(&self) -> &CommitTree;

    /// Delete all events from the log file on disc
    /// and in-memory.
    async fn clear(&mut self) -> Result<(), Self::Error>;

    /// Rewind this event log discarding commits after
    /// the specific commit.
    ///
    /// Returns the collection of log records that can
    /// be used to revert if a subsequent merge fails.
    async fn rewind(
        &mut self,
        commit: &CommitHash,
    ) -> Result<Vec<EventRecord>, Self::Error>;

    /// Load data from storage to build a commit tree in memory.
    async fn load_tree(&mut self) -> Result<(), Self::Error>;

    /// Stream of event records.
    ///
    /// # Panics
    ///
    /// If the iterator cannot be initialized.
    async fn record_stream(
        &self,
        reverse: bool,
    ) -> BoxStream<'async_trait, Result<EventRecord, Self::Error>>;

    /// Stream of event records and decoded events.
    ///
    /// # Panics
    ///
    /// If the iterator cannot be initialized.
    async fn event_stream(
        &self,
        reverse: bool,
    ) -> BoxStream<'async_trait, Result<(EventRecord, E), Self::Error>>;

    /// Create a checked diff from a commit.
    ///
    /// Used when merging to verify that the HEAD of the
    /// event log matches the checkpoint before applying
    /// the patch.
    async fn diff_checked(
        &self,
        commit: Option<CommitHash>,
        checkpoint: CommitProof,
    ) -> Result<Diff<E>, Self::Error>;

    /// Create an unchecked diff of all events.
    ///
    /// Used during a force merge to overwrite an event log
    /// with new events.
    ///
    /// For example, when destructive changes are made (change
    /// cipher or password) then other devices need to rewrite
    /// the event logs.
    async fn diff_unchecked(&self) -> Result<Diff<E>, Self::Error>;

    /// Diff of events until a specific commit; does
    /// not include the target commit.
    ///
    /// If no commit hash is given then all events are included.
    async fn diff_events(
        &self,
        commit: Option<&CommitHash>,
    ) -> Result<Patch<E>, Self::Error>;

    /// Append a collection of events and commit the tree hashes
    /// only if all the events were successfully written.
    async fn apply(&mut self, events: Vec<&E>) -> Result<(), Self::Error>;

    /// Append raw event records to the event log.
    ///
    /// Use this to preserve the time information in
    /// existing event records.
    async fn apply_records(
        &mut self,
        records: Vec<EventRecord>,
    ) -> Result<(), Self::Error>;

    /// Append a patch to this event log only if the
    /// head of the tree matches the given proof.
    async fn patch_checked(
        &mut self,
        commit_proof: &CommitProof,
        patch: &Patch<E>,
    ) -> Result<CheckedPatch, Self::Error>;

    /// Replace all events in this event log with the events in the diff.
    ///
    /// For disc based implementations a snapshot is created
    /// of the event log file beforehand by copying the event
    /// log to a new file with a `snapshot-{root_hash}` file extension.
    ///
    /// The events on disc and the in-memory merkle tree are then
    /// removed before applying the patch in the diff.
    ///
    /// After applying the events if the HEAD of the event log
    /// does not match the `checkpoint` in the diff verification
    /// fails and an attempt is made to rollback to the snapshot.
    ///
    /// When verification fails an [Error::CheckpointVerification]
    /// error will always be returned.
    async fn replace_all_events(
        &mut self,
        diff: &Diff<E>,
    ) -> Result<(), Self::Error>;

    /// Append a patch to this event log.
    async fn patch_unchecked(
        &mut self,
        patch: &Patch<E>,
    ) -> Result<(), Self::Error>;

    /// Diff of event records until a specific commit.
    ///
    /// Searches backwards until it finds the specified commit
    /// if given; if no commit is given the diff will include
    /// all event records.
    ///
    /// Does not include the target commit.
    async fn diff_records(
        &self,
        commit: Option<&CommitHash>,
    ) -> Result<Vec<EventRecord>, Self::Error>;

    /// Encoding version.
    fn version(&self) -> u16;
}
