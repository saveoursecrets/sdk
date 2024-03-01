use crate::{
    commit::{CommitHash, CommitProof, CommitState},
    encoding::encoding_error,
};
use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use rs_merkle::{algorithms::Sha256, MerkleProof};
use std::io::Result;

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

        writer.write_u32(self.length as u32).await?;
        writer.write_u32(self.indices.start as u32).await?;
        writer.write_u32(self.indices.end as u32).await?;
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
        self.length = reader.read_u32().await? as usize;
        let start = reader.read_u32().await?;
        let end = reader.read_u32().await?;

        // TODO: validate range start is <= range end

        self.indices = start as usize..end as usize;
        Ok(())
    }
}