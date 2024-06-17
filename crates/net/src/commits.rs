//! Types for scanning commit history in event logs.
use crate::sdk::{
    commit::{CommitHash, CommitProof},
    events::{EventLogType, EventRecord},
};
use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use std::io::Result;

/// Request to patch an event log from a specific commit.
///
/// Used during auto merge to force push a combined collection
/// of events.
#[derive(Debug, Default)]
pub struct EventPatchRequest {
    /// Type of event log to patch.
    pub log_type: EventLogType,
    /// Hash of the commit to rewind to before
    /// applying the patch.
    pub commit: Option<CommitHash>,
    /// Proof for head of the event log before the
    /// events are applied.
    pub proof: CommitProof,
    /// Patch of events to apply.
    pub patch: Vec<EventRecord>,
}

#[async_trait]
impl Encodable for EventPatchRequest {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        self.log_type.encode(&mut *writer).await?;
        self.commit.encode(&mut *writer).await?;
        self.proof.encode(&mut *writer).await?;
        self.patch.encode(&mut *writer).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for EventPatchRequest {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        self.log_type.decode(&mut *reader).await?;
        self.commit.decode(&mut *reader).await?;
        self.proof.decode(&mut *reader).await?;
        self.patch.decode(&mut *reader).await?;
        Ok(())
    }
}