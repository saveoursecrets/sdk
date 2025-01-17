use crate::formats::{EventLogRecord, FileRecord, VaultRecord};
use async_trait::async_trait;
use binary_stream::futures::{BinaryReader, Decodable};
use sos_core::encoding::encoding_error;
use std::io::Result;
use tokio::io::{AsyncRead, AsyncSeek};

#[async_trait]
impl Decodable for EventLogRecord {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        self.time.decode(&mut *reader).await?;
        self.last_commit = reader
            .read_bytes(32)
            .await?
            .as_slice()
            .try_into()
            .map_err(encoding_error)?;
        self.commit = reader
            .read_bytes(32)
            .await?
            .as_slice()
            .try_into()
            .map_err(encoding_error)?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for FileRecord {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        _reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl Decodable for VaultRecord {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let id: [u8; 16] = reader
            .read_bytes(16)
            .await?
            .as_slice()
            .try_into()
            .map_err(encoding_error)?;
        let commit: [u8; 32] = reader
            .read_bytes(32)
            .await?
            .as_slice()
            .try_into()
            .map_err(encoding_error)?;

        self.id = id;
        self.commit = commit;
        Ok(())
    }
}
