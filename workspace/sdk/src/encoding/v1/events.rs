use crate::{
    commit::CommitHash,
    crypto::AeadPack,
    encoding::{decode_uuid, encoding_error},
    events::{
        EventKind, EventRecord,
        LogEvent, WriteEvent,
    },
    formats::{EventLogRecord, FileRecord, VaultRecord},
    vault::VaultCommit,
    Timestamp,
};

use crate::events::AccountEvent;

#[cfg(feature = "files")]
use crate::events::FileEvent;

use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use std::io::{Error, ErrorKind, Result, SeekFrom};

use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};

#[async_trait]
impl Encodable for EventKind {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let value: u16 = self.into();
        writer.write_u16(value).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for EventKind {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let op = reader.read_u16().await?;
        *self = op.try_into().map_err(|_| {
            Error::new(ErrorKind::Other, format!("unknown event kind {}", op))
        })?;
        Ok(())
    }
}

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
        let mut time: Timestamp = Default::default();
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
impl Encodable for WriteEvent {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let op = self.event_kind();
        op.encode(&mut *writer).await?;

        match self {
            WriteEvent::Noop => {
                panic!("attempt to encode a noop")
            }
            WriteEvent::CreateVault(vault) => {
                writer.write_u32(vault.len() as u32).await?;
                writer.write_bytes(vault).await?;
            }
            WriteEvent::SetVaultName(name) => {
                writer.write_string(name).await?;
            }
            WriteEvent::SetVaultMeta(meta) => {
                meta.encode(&mut *writer).await?;
            }
            WriteEvent::CreateSecret(uuid, value) => {
                writer.write_bytes(uuid.as_bytes()).await?;
                value.encode(&mut *writer).await?;
            }
            WriteEvent::UpdateSecret(uuid, value) => {
                writer.write_bytes(uuid.as_bytes()).await?;
                value.encode(&mut *writer).await?;
            }
            WriteEvent::DeleteSecret(uuid) => {
                writer.write_bytes(uuid.as_bytes()).await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Decodable for WriteEvent {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let mut op: EventKind = Default::default();
        op.decode(&mut *reader).await?;
        match op {
            EventKind::Noop => panic!("attempt to decode a noop"),
            EventKind::CreateVault => {
                let length = reader.read_u32().await?;
                let buffer = reader.read_bytes(length as usize).await?;
                *self = WriteEvent::CreateVault(buffer);
            }
            EventKind::SetVaultName => {
                let name = reader.read_string().await?;
                *self = WriteEvent::SetVaultName(name);
            }
            EventKind::SetVaultMeta => {
                let mut aead_pack: AeadPack = Default::default();
                aead_pack.decode(&mut *reader).await?;
                *self = WriteEvent::SetVaultMeta(aead_pack);
            }
            EventKind::CreateSecret => {
                let id = decode_uuid(&mut *reader).await?;
                let mut commit: VaultCommit = Default::default();
                commit.decode(&mut *reader).await?;
                *self = WriteEvent::CreateSecret(id, commit);
            }
            EventKind::UpdateSecret => {
                let id = decode_uuid(&mut *reader).await?;
                let mut commit: VaultCommit = Default::default();
                commit.decode(&mut *reader).await?;
                *self = WriteEvent::UpdateSecret(id, commit);
            }
            EventKind::DeleteSecret => {
                let id = decode_uuid(&mut *reader).await?;
                *self = WriteEvent::DeleteSecret(id);
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("unknown event kind {}", op),
                ));
            }
        }
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

#[async_trait]
impl Encodable for AccountEvent {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let op = self.event_kind();
        op.encode(&mut *writer).await?;

        match self {
            AccountEvent::Noop => panic!("attempt to encode a noop"),
            AccountEvent::UpdateFolder(id, buffer)
            | AccountEvent::CompactFolder(id, buffer)
            | AccountEvent::ChangeFolderPassword(id, buffer)
            | AccountEvent::CreateFolder(id, buffer) => {
                writer.write_bytes(id.as_bytes()).await?;
                writer.write_u32(buffer.len() as u32).await?;
                writer.write_bytes(buffer).await?;
            }
            AccountEvent::RenameFolder(id, name) => {
                writer.write_bytes(id.as_bytes()).await?;
                writer.write_string(name).await?;
            }
            AccountEvent::DeleteFolder(id) => {
                writer.write_bytes(id.as_bytes()).await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Decodable for AccountEvent {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let mut op: EventKind = Default::default();
        op.decode(&mut *reader).await?;
        match op {
            EventKind::Noop => panic!("attempt to decode a noop"),
            EventKind::CreateVault => {
                let id = decode_uuid(&mut *reader).await?;
                let len = reader.read_u32().await?;
                let buffer = reader.read_bytes(len as usize).await?;
                *self = AccountEvent::CreateFolder(id, buffer)
            }
            EventKind::ChangePassword => {
                let id = decode_uuid(&mut *reader).await?;
                let len = reader.read_u32().await?;
                let buffer = reader.read_bytes(len as usize).await?;
                *self = AccountEvent::ChangeFolderPassword(id, buffer)
            }
            EventKind::UpdateVault => {
                let id = decode_uuid(&mut *reader).await?;
                let len = reader.read_u32().await?;
                let buffer = reader.read_bytes(len as usize).await?;
                *self = AccountEvent::UpdateFolder(id, buffer)
            }
            EventKind::CompactVault => {
                let id = decode_uuid(&mut *reader).await?;
                let len = reader.read_u32().await?;
                let buffer = reader.read_bytes(len as usize).await?;
                *self = AccountEvent::CompactFolder(id, buffer)
            }
            EventKind::SetVaultName => {
                let id = decode_uuid(&mut *reader).await?;
                let name = reader.read_string().await?;
                *self = AccountEvent::RenameFolder(id, name);
            }
            EventKind::DeleteVault => {
                let id = decode_uuid(&mut *reader).await?;
                *self = AccountEvent::DeleteFolder(id);
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("unknown account event kind {}", op),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(feature = "files")]
#[async_trait]
impl Encodable for FileEvent {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let op = self.event_kind();
        op.encode(&mut *writer).await?;
        match self {
            FileEvent::Noop => panic!("attempt to encode a noop"),
            FileEvent::CreateFile(folder_id, secret_id, name)
            | FileEvent::DeleteFile(folder_id, secret_id, name) => {
                writer.write_bytes(folder_id.as_bytes()).await?;
                writer.write_bytes(secret_id.as_bytes()).await?;
                writer.write_bytes(name.as_ref()).await?;
            }
            FileEvent::MoveFile { name, from, dest } => {
                writer.write_bytes(name.as_ref()).await?;
                writer.write_bytes(from.0.as_bytes()).await?;
                writer.write_bytes(from.1.as_bytes()).await?;
                writer.write_bytes(dest.0.as_bytes()).await?;
                writer.write_bytes(dest.1.as_bytes()).await?;
            }
        }
        Ok(())
    }
}

#[cfg(feature = "files")]
#[async_trait]
impl Decodable for FileEvent {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let mut op: EventKind = Default::default();
        op.decode(&mut *reader).await?;
        match op {
            EventKind::Noop => panic!("attempt to decode a noop"),
            EventKind::CreateFile => {
                let folder_id = decode_uuid(&mut *reader).await?;
                let secret_id = decode_uuid(&mut *reader).await?;
                let name = reader.read_bytes(32).await?;
                let name: [u8; 32] =
                    name.as_slice().try_into().map_err(encoding_error)?;
                *self =
                    FileEvent::CreateFile(folder_id, secret_id, name.into())
            }
            EventKind::DeleteFile => {
                let folder_id = decode_uuid(&mut *reader).await?;
                let secret_id = decode_uuid(&mut *reader).await?;
                let name = reader.read_bytes(32).await?;
                let name: [u8; 32] =
                    name.as_slice().try_into().map_err(encoding_error)?;
                *self =
                    FileEvent::DeleteFile(folder_id, secret_id, name.into())
            }
            EventKind::MoveFile => {
                let name = reader.read_bytes(32).await?;
                let name: [u8; 32] =
                    name.as_slice().try_into().map_err(encoding_error)?;
                let from = (
                    decode_uuid(&mut *reader).await?,
                    decode_uuid(&mut *reader).await?,
                );
                let dest = (
                    decode_uuid(&mut *reader).await?,
                    decode_uuid(&mut *reader).await?,
                );
                *self = FileEvent::MoveFile {
                    name: name.into(),
                    from,
                    dest,
                }
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("unknown file event kind {}", op),
                ));
            }
        }
        Ok(())
    }
}
