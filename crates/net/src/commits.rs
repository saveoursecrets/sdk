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

/// Request commit proofs from an event log.
#[derive(Debug, Default, Clone)]
pub struct CommitScanRequest {
    /// Type of event log to load commit hashes from.
    pub log_type: EventLogType,
    /// Number of proofs to fetch.
    ///
    /// Server implementations should restrict this to
    /// a sensible amount; the default server implementation
    /// imposes a limit of 256 proofs.
    pub limit: u16,
    /// Offset from a previous scan used as a hint to
    /// continue scanning.
    ///
    /// The zero offset is always the start of the scan
    /// regardless of whether the scan is ascending (from
    /// the first commit) or descending (from the last commit).
    pub offset: Option<u64>,
    /// Scan in ascending order from the first commit.
    ///
    /// Default behavior is to scan from the end
    /// of the event log.
    pub ascending: bool,
}

/// Commit proofs from an event log.
#[derive(Debug, Default)]
pub struct CommitScanResponse {
    /// List of commit proofs.
    ///
    /// Proofs are always listed in the order they
    /// appear in the event log regardless of the scan
    /// direction.
    pub proofs: Vec<CommitProof>,
    /// Offset that can be used to continue scanning.
    pub offset: u64,
}

/// Request commit diff from an event log.
#[derive(Debug, Default)]
pub struct CommitDiffRequest {
    /// Type of event log to load the diff from.
    pub log_type: EventLogType,
    /// Hash of the commit to diff from.
    pub from_hash: CommitHash,
}

/// Response with an event log commit diff.
#[derive(Debug, Default)]
pub struct CommitDiffResponse {
    /// Collection of event records from the commit hash.
    pub patch: Vec<EventRecord>,
}

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
impl Encodable for CommitScanRequest {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        self.log_type.encode(&mut *writer).await?;
        self.limit.encode(&mut *writer).await?;
        self.offset.encode(&mut *writer).await?;
        self.ascending.encode(&mut *writer).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for CommitScanRequest {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        self.log_type.decode(&mut *reader).await?;
        self.limit.decode(&mut *reader).await?;
        self.offset.decode(&mut *reader).await?;
        self.ascending.decode(&mut *reader).await?;
        Ok(())
    }
}

#[async_trait]
impl Encodable for CommitScanResponse {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        self.offset.encode(&mut *writer).await?;
        self.proofs.encode(&mut *writer).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for CommitScanResponse {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        self.offset.decode(&mut *reader).await?;
        self.proofs.decode(&mut *reader).await?;
        Ok(())
    }
}

#[async_trait]
impl Encodable for CommitDiffRequest {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        self.log_type.encode(&mut *writer).await?;
        self.from_hash.encode(&mut *writer).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for CommitDiffRequest {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        self.log_type.decode(&mut *reader).await?;
        self.from_hash.decode(&mut *reader).await?;
        Ok(())
    }
}

#[async_trait]
impl Encodable for CommitDiffResponse {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        self.patch.encode(&mut *writer).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for CommitDiffResponse {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        self.patch.decode(&mut *reader).await?;
        Ok(())
    }
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
        self.proof.decode(&mut *reader).await?;
        self.patch.decode(&mut *reader).await?;
        Ok(())
    }
}
