use sos_core::{
    crypto::AeadPack,
    encoding::{decode_uuid, encoding_error},
    events::{AccountEvent, EventKind, LogEvent, WriteEvent},
    UtcDateTime, VaultCommit, VaultFlags,
};

use crate::events::EventRecord;
use crate::formats::{EventLogRecord, FileRecord, VaultRecord};
use sos_core::commit::CommitHash;
use sos_core::events::DeviceEvent;

#[cfg(feature = "files")]
use sos_core::{events::FileEvent, SecretPath};

use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use std::io::{Error, ErrorKind, Result, SeekFrom};

use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};

#[async_trait]
impl Encodable for EventRecord {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        // Prepare the bytes for the row length
        let size_pos = writer.stream_position().await?;
        writer.write_u32(0).await?;

        // Encodable the time component
        self.0.encode(&mut *writer).await?;

        // Write the previous commit hash bytes
        writer.write_bytes(self.1.as_ref()).await?;

        // Write the commit hash bytes
        writer.write_bytes(self.2.as_ref()).await?;

        // FIXME: ensure the buffer size does not exceed u32

        // Write the data bytes
        writer.write_u32(self.3.len() as u32).await?;
        writer.write_bytes(&self.3).await?;

        // Backtrack to size_pos and write new length
        let row_pos = writer.stream_position().await?;
        let row_len = row_pos - (size_pos + 4);
        writer.seek(SeekFrom::Start(size_pos)).await?;
        writer.write_u32(row_len as u32).await?;
        writer.seek(SeekFrom::Start(row_pos)).await?;

        // Write out the row len at the end of the record too
        // so we can support double ended iteration
        writer.write_u32(row_len as u32).await?;

        Ok(())
    }
}

#[async_trait]
impl Decodable for EventRecord {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        // Read in the row length
        let _ = reader.read_u32().await?;

        // Decodable the time component
        let mut time: UtcDateTime = Default::default();
        time.decode(&mut *reader).await?;

        // Read the hash bytes
        let previous: [u8; 32] = reader
            .read_bytes(32)
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

        // Read the data bytes
        let length = reader.read_u32().await?;
        let buffer = reader.read_bytes(length as usize).await?;

        self.0 = time;
        self.1 = CommitHash(previous);
        self.2 = CommitHash(commit);
        self.3 = buffer;

        // Read in the row length appended to the end of the record
        let _ = reader.read_u32().await?;

        Ok(())
    }
}

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