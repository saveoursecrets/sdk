use crate::{
    VaultCommit, VaultEntry, commit::CommitHash, crypto::AeadPack,
    encoding::encoding_error,
};
use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use std::io::{Result, SeekFrom};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite};

#[async_trait]
impl Encodable for VaultEntry {
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
impl Decodable for VaultEntry {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let mut meta: AeadPack = Default::default();
        meta.decode(&mut *reader).await?;
        let mut secret: AeadPack = Default::default();
        secret.decode(&mut *reader).await?;
        *self = VaultEntry(meta, secret);
        Ok(())
    }
}

#[async_trait]
impl Encodable for VaultCommit {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        // Write the UUID
        writer.write_bytes(self.0.as_ref()).await?;

        let size_pos = writer.stream_position().await?;

        writer.write_u32(0).await?;

        self.1.encode(&mut *writer).await?;

        // Encodable the data length for lazy iteration
        let row_pos = writer.stream_position().await?;
        let row_len = row_pos - (size_pos + 4);
        writer.seek(SeekFrom::Start(size_pos)).await?;
        writer.write_u32(row_len as u32).await?;
        writer.seek(SeekFrom::Start(row_pos)).await?;

        Ok(())
    }
}

#[async_trait]
impl Decodable for VaultCommit {
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
        let commit = CommitHash(commit);

        // Read in the length of the data blob
        let _ = reader.read_u32().await?;

        let mut group: VaultEntry = Default::default();
        group.decode(&mut *reader).await?;
        self.0 = commit;
        self.1 = group;
        Ok(())
    }
}
