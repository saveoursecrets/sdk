use crate::encoding::encoding_error;
use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use sos_core::{
    commit,
    merkle::{algorithms::Sha256, MerkleProof},
};
use std::io::{Error, ErrorKind, Result};

#[doc(hidden)]
#[derive(Default)]
pub struct CommitHash(commit::CommitHash);

impl AsRef<[u8]> for CommitHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<commit::CommitHash> for CommitHash {
    fn from(value: commit::CommitHash) -> Self {
        Self(value)
    }
}

#[doc(hidden)]
pub struct CommitState(CommitHash, CommitProof);

impl From<commit::CommitState> for CommitState {
    fn from(value: commit::CommitState) -> Self {
        Self(value.0.into(), value.1.into())
    }
}

#[doc(hidden)]
#[derive(Default)]
pub struct CommitProof(commit::CommitProof);

impl AsRef<commit::CommitProof> for CommitProof {
    fn as_ref(&self) -> &commit::CommitProof {
        &self.0
    }
}

impl From<commit::CommitProof> for CommitProof {
    fn from(value: commit::CommitProof) -> Self {
        Self(value)
    }
}

#[doc(hidden)]
#[derive(Default)]
pub struct Comparison(commit::Comparison);

impl AsRef<commit::Comparison> for Comparison {
    fn as_ref(&self) -> &commit::Comparison {
        &self.0
    }
}

impl From<commit::Comparison> for Comparison {
    fn from(value: commit::Comparison) -> Self {
        Self(value)
    }
}

#[async_trait]
impl Encodable for CommitHash {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_bytes(self.as_ref()).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for CommitHash {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let commit: [u8; 32] = reader
            .read_bytes(32)
            .await?
            .as_slice()
            .try_into()
            .map_err(encoding_error)?;
        *self = commit::CommitHash(commit).into();
        Ok(())
    }
}

#[async_trait]
impl Encodable for CommitState {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        self.0.encode(&mut *writer).await?;
        self.1.encode(&mut *writer).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for CommitState {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let mut hash: CommitHash = Default::default();
        let mut proof: CommitProof = Default::default();
        hash.decode(&mut *reader).await?;
        proof.decode(&mut *reader).await?;
        *self = CommitState(hash, proof);
        Ok(())
    }
}

#[async_trait]
impl Encodable for CommitProof {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_bytes(self.as_ref().root.as_ref()).await?;
        let proof_bytes = self.as_ref().proof.to_bytes();
        writer.write_u32(proof_bytes.len() as u32).await?;
        writer.write_bytes(&proof_bytes).await?;

        self.as_ref().length.encode(&mut *writer).await?;
        self.as_ref().indices.encode(&mut *writer).await?;

        Ok(())
    }
}

#[async_trait]
impl Decodable for CommitProof {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let root_hash: [u8; 32] = reader
            .read_bytes(32)
            .await?
            .as_slice()
            .try_into()
            .map_err(encoding_error)?;

        let mut inner: commit::CommitProof = Default::default();

        inner.root = commit::CommitHash(root_hash);

        let length = reader.read_u32().await?;
        let proof_bytes = reader.read_bytes(length as usize).await?;
        let proof = MerkleProof::<Sha256>::from_bytes(&proof_bytes)
            .map_err(encoding_error)?;
        inner.proof = proof;

        inner.length.decode(&mut *reader).await?;
        inner.indices.decode(&mut *reader).await?;

        *self = inner.into();

        Ok(())
    }
}

#[async_trait]
impl Encodable for Comparison {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        match &self.0 {
            commit::Comparison::Equal => {
                writer.write_u8(1).await?;
            }
            commit::Comparison::Contains(indices) => {
                writer.write_u8(2).await?;
                writer.write_u32(indices.len() as u32).await?;
                for i in indices {
                    writer.write_u64(*i as u64).await?;
                }
            }
            commit::Comparison::Unknown => {
                writer.write_u8(3).await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Decodable for Comparison {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let kind = reader.read_u8().await?;
        match kind {
            1 => {
                *self = commit::Comparison::Equal.into();
            }
            2 => {
                let indices_len = reader.read_u32().await? as usize;
                let mut indices = Vec::with_capacity(indices_len);
                for _ in 0..indices_len {
                    indices.push(reader.read_u64().await? as usize);
                }

                *self = commit::Comparison::Contains(indices).into();
            }
            3 => {
                *self = commit::Comparison::Unknown.into();
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("unknown comparison variant kind {}", kind),
                ));
            }
        }
        Ok(())
    }
}
