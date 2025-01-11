//! Event log backed by a database table.
use async_trait::async_trait;
use binary_stream::futures::{Decodable, Encodable};
use futures::stream::BoxStream;
use sos_core::{
    commit::{CommitHash, CommitProof, CommitTree},
    events::{
        patch::{CheckedPatch, Diff, Patch},
        EventLog, EventRecord,
    },
};

/// Database event log.
pub struct DatabaseEventLog<T, E>
where
    T: Default + Encodable + Decodable + Send + Sync,
    E: std::error::Error
        + std::fmt::Debug
        + From<sos_core::Error>
        + From<crate::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    tree: CommitTree,
    marker: std::marker::PhantomData<(T, E)>,
}

#[async_trait]
impl<T, E> EventLog<T> for DatabaseEventLog<T, E>
where
    T: Default + Encodable + Decodable + Send + Sync + 'static,
    E: std::error::Error
        + std::fmt::Debug
        + From<sos_core::Error>
        + From<crate::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    type Error = E;

    async fn stream(
        &self,
        reverse: bool,
    ) -> BoxStream<'static, Result<(EventRecord, T), Self::Error>> {
        todo!();
    }

    async fn diff_checked(
        &self,
        commit: Option<CommitHash>,
        checkpoint: CommitProof,
    ) -> Result<Diff<T>, Self::Error> {
        todo!();
    }

    async fn diff_unchecked(&self) -> Result<Diff<T>, Self::Error> {
        let patch = self.diff_events(None).await?;
        Ok(Diff::<T> {
            last_commit: None,
            patch,
            checkpoint: self.tree().head()?,
        })
    }

    async fn diff_events(
        &self,
        commit: Option<&CommitHash>,
    ) -> Result<Patch<T>, Self::Error> {
        let records = self.diff_records(commit).await?;
        Ok(Patch::new(records))
    }

    fn tree(&self) -> &CommitTree {
        &self.tree
    }

    fn identity(&self) -> &'static [u8] {
        todo!();
    }

    fn version(&self) -> Option<u16> {
        todo!();
    }

    async fn truncate(&mut self) -> Result<(), Self::Error> {
        todo!();
    }

    async fn rewind(
        &mut self,
        commit: &CommitHash,
    ) -> Result<Vec<EventRecord>, Self::Error> {
        todo!();
    }

    async fn load_tree(&mut self) -> Result<(), Self::Error> {
        todo!();
    }

    async fn clear(&mut self) -> Result<(), Self::Error> {
        todo!();
    }

    async fn apply(&mut self, events: Vec<&T>) -> Result<(), Self::Error> {
        todo!();
    }

    async fn apply_records(
        &mut self,
        records: Vec<EventRecord>,
    ) -> Result<(), Self::Error> {
        todo!();
    }

    async fn patch_checked(
        &mut self,
        commit_proof: &CommitProof,
        patch: &Patch<T>,
    ) -> Result<CheckedPatch, Self::Error> {
        todo!();
    }

    async fn patch_replace(
        &mut self,
        diff: &Diff<T>,
    ) -> Result<(), Self::Error> {
        todo!();
    }

    async fn patch_unchecked(
        &mut self,
        patch: &Patch<T>,
    ) -> Result<(), Self::Error> {
        todo!();
    }

    async fn diff_records(
        &self,
        commit: Option<&CommitHash>,
    ) -> Result<Vec<EventRecord>, Self::Error> {
        todo!();
    }

    #[doc(hidden)]
    async fn read_file_version(&self) -> Result<u16, Self::Error> {
        todo!();
    }
}
