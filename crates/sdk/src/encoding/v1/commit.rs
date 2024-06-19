use crate::{
    commit::{CommitHash, CommitProof, CommitState, Comparison},
    encoding::encoding_error,
};
use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use rs_merkle::{algorithms::Sha256, MerkleProof};
use std::io::{Error, ErrorKind, Result};

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
        *self = CommitHash(commit);
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
        self.0.decode(&mut *reader).await?;
        self.1.decode(&mut *reader).await?;
        Ok(())
    }
}

#[async_trait]
impl Encodable for CommitProof {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_bytes(self.root.as_ref()).await?;
        let proof_bytes = self.proof.to_bytes();
        writer.write_u32(proof_bytes.len() as u32).await?;
        writer.write_bytes(&proof_bytes).await?;

        self.length.encode(&mut *writer).await?;
        self.indices.encode(&mut *writer).await?;

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
        self.root = CommitHash(root_hash);

        let length = reader.read_u32().await?;
        let proof_bytes = reader.read_bytes(length as usize).await?;
        let proof = MerkleProof::<Sha256>::from_bytes(&proof_bytes)
            .map_err(encoding_error)?;
        self.proof = proof;

        self.length.decode(&mut *reader).await?;
        self.indices.decode(&mut *reader).await?;
        Ok(())
    }
}

#[async_trait]
impl Encodable for Comparison {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        match self {
            Self::Equal => {
                writer.write_u8(1).await?;
            }
            Self::Contains(indices) => {
                writer.write_u8(2).await?;
                writer.write_u32(indices.len() as u32).await?;
                for i in indices {
                    writer.write_u64(*i as u64).await?;
                }
            }
            Self::Unknown => {
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
                *self = Self::Equal;
            }
            2 => {
                let indices_len = reader.read_u32().await? as usize;
                let mut indices = Vec::with_capacity(indices_len);
                for _ in 0..indices_len {
                    indices.push(reader.read_u64().await? as usize);
                }

                *self = Self::Contains(indices);
            }
            3 => {
                *self = Self::Unknown;
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
