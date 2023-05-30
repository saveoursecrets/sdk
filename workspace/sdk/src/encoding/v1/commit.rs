use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite,
    AsyncWriteExt,
};

use async_trait::async_trait;
use binary_stream::{
    tokio::{BinaryReader, BinaryWriter, Decode, Encode},
    BinaryError, BinaryResult,
};

use rs_merkle::{algorithms::Sha256, MerkleProof};

use crate::commit::CommitProof;

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for CommitProof {
    async fn encode<W: AsyncWriteExt + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        writer.write_bytes(self.root).await?;
        let proof_bytes = self.proof.to_bytes();
        writer.write_u32(proof_bytes.len() as u32).await?;
        writer.write_bytes(&proof_bytes).await?;

        writer.write_u32(self.length as u32).await?;
        writer.write_u32(self.indices.start as u32).await?;
        writer.write_u32(self.indices.end as u32).await?;
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for CommitProof {
    async fn decode<R: AsyncReadExt + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        let root_hash: [u8; 32] =
            reader.read_bytes(32).await?.as_slice().try_into()?;
        self.root = root_hash;
        let length = reader.read_u32().await?;
        let proof_bytes = reader.read_bytes(length as usize).await?;
        let proof = MerkleProof::<Sha256>::from_bytes(&proof_bytes)
            .map_err(Box::from)?;

        self.proof = proof;
        self.length = reader.read_u32().await? as usize;
        let start = reader.read_u32().await?;
        let end = reader.read_u32().await?;

        // TODO: validate range start is <= range end

        self.indices = start as usize..end as usize;
        Ok(())
    }
}
