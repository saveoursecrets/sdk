use crate::{
    commit::CommitHash,
    constants::PATCH_IDENTITY,
    crypto::{AeadPack, SecureAccessKey},
    encoding::{decode_uuid, encoding_error},
    events::{
        AuditData, AuditEvent, AuditLogFile, EventKind, EventRecord,
        LogEvent, LogFlags, Patch, WriteEvent,
    },
    formats::{EventLogFileRecord, FileIdentity, FileRecord, VaultRecord},
    vault::{secret::SecretId, VaultCommit},
    Timestamp,
};

#[cfg(feature = "account")]
use crate::events::AccountEvent;

#[cfg(feature = "files")]
use crate::events::FileEvent;

use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use std::io::{Error, ErrorKind, Result, SeekFrom};

use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};

use uuid::Uuid;

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
impl Encodable for AuditEvent {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        // Context bit flags
        let flags = self.log_flags();
        writer.write_u16(flags.bits()).await?;
        // Time - the when
        self.time.encode(&mut *writer).await?;
        // EventKind - the what
        self.event_kind.encode(&mut *writer).await?;
        // Address - by whom
        writer.write_bytes(self.address.as_ref()).await?;
        // Data - context
        if flags.contains(LogFlags::DATA) {
            let data = self.data.as_ref().unwrap();
            data.encode(&mut *writer).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Decodable for AuditEvent {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        // Context bit flags
        let bits = reader.read_u16().await?;
        // Time - the when
        let mut timestamp: Timestamp = Default::default();
        timestamp.decode(&mut *reader).await?;
        self.time = timestamp;
        // EventKind - the what
        self.event_kind.decode(&mut *reader).await?;
        // Address - by whom
        let address = reader.read_bytes(20).await?;
        let address: [u8; 20] =
            address.as_slice().try_into().map_err(encoding_error)?;
        self.address = address.into();
        // Data - context
        if let Some(flags) = LogFlags::from_bits(bits) {
            if flags.contains(LogFlags::DATA) {
                if flags.contains(LogFlags::DATA_VAULT) {
                    let vault_id = decode_uuid(&mut *reader).await?;
                    if !flags.contains(LogFlags::DATA_SECRET) {
                        self.data = Some(AuditData::Vault(vault_id));
                    } else {
                        let secret_id = decode_uuid(&mut *reader).await?;
                        self.data =
                            Some(AuditData::Secret(vault_id, secret_id));
                    }
                } else if flags.contains(LogFlags::MOVE_SECRET) {
                    let from_vault_id = decode_uuid(&mut *reader).await?;
                    let from_secret_id = decode_uuid(&mut *reader).await?;
                    let to_vault_id = decode_uuid(&mut *reader).await?;
                    let to_secret_id = decode_uuid(&mut *reader).await?;
                    self.data = Some(AuditData::MoveSecret {
                        from_vault_id,
                        from_secret_id,
                        to_vault_id,
                        to_secret_id,
                    });
                }
            }
        } else {
            return Err(Error::new(
                ErrorKind::Other,
                "log data flags has bad bits",
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl Encodable for AuditData {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        match self {
            AuditData::Vault(vault_id) => {
                writer.write_bytes(vault_id.as_bytes()).await?;
            }
            AuditData::Secret(vault_id, secret_id) => {
                writer.write_bytes(vault_id.as_bytes()).await?;
                writer.write_bytes(secret_id.as_bytes()).await?;
            }
            AuditData::MoveSecret {
                from_vault_id,
                from_secret_id,
                to_vault_id,
                to_secret_id,
            } => {
                writer.write_bytes(from_vault_id.as_bytes()).await?;
                writer.write_bytes(from_secret_id.as_bytes()).await?;
                writer.write_bytes(to_vault_id.as_bytes()).await?;
                writer.write_bytes(to_secret_id.as_bytes()).await?;
            }
        }
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
            WriteEvent::CreateVault(vault)
            | WriteEvent::UpdateVault(vault) => {
                writer.write_u32(vault.len() as u32).await?;
                writer.write_bytes(vault).await?;
            }
            WriteEvent::DeleteVault => {}
            WriteEvent::SetVaultName(name) => {
                writer.write_string(name).await?;
            }
            WriteEvent::SetVaultMeta(meta) => {
                writer.write_bool(meta.is_some()).await?;
                if let Some(meta) = meta {
                    meta.encode(&mut *writer).await?;
                }
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
            EventKind::UpdateVault => {
                let length = reader.read_u32().await?;
                let buffer = reader.read_bytes(length as usize).await?;
                *self = WriteEvent::UpdateVault(buffer);
            }
            EventKind::DeleteVault => {
                *self = WriteEvent::DeleteVault;
            }
            EventKind::SetVaultName => {
                let name = reader.read_string().await?;
                *self = WriteEvent::SetVaultName(name);
            }
            EventKind::SetVaultMeta => {
                let has_meta = reader.read_bool().await?;
                let aead_pack = if has_meta {
                    let mut aead_pack: AeadPack = Default::default();
                    aead_pack.decode(&mut *reader).await?;
                    Some(aead_pack)
                } else {
                    None
                };
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
impl Decodable for EventLogFileRecord {
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

impl AuditLogFile {
    /// Encodable an audit log event record.
    pub(crate) async fn encode_row<
        W: AsyncWrite + AsyncSeek + Unpin + Send,
    >(
        writer: &mut BinaryWriter<W>,
        event: AuditEvent,
    ) -> Result<()> {
        // Set up the leading row length
        let size_pos = writer.stream_position().await?;
        writer.write_u32(0).await?;

        // Encodable the event data for the row
        event.encode(&mut *writer).await?;

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

    /// Decodable an audit log event record.
    pub(crate) async fn decode_row<
        R: AsyncRead + AsyncSeek + Unpin + Send,
    >(
        reader: &mut BinaryReader<R>,
    ) -> Result<AuditEvent> {
        // Read in the row length
        let _ = reader.read_u32().await?;

        let mut event: AuditEvent = Default::default();
        event.decode(&mut *reader).await?;

        // Read in the row length appended to the end of the record
        let _ = reader.read_u32().await?;
        Ok(event)
    }
}

#[async_trait]
impl Encodable for Patch {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_bytes(PATCH_IDENTITY).await?;
        for event in self.0.iter() {
            event.encode(writer).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Decodable for Patch {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        FileIdentity::read_identity(reader, &PATCH_IDENTITY)
            .await
            .map_err(encoding_error)?;
        let mut pos = reader.stream_position().await?;
        let len = reader.len().await?;
        while pos < len {
            let mut event: EventRecord = Default::default();
            event.decode(reader).await?;
            self.0.push(event);
            pos = reader.stream_position().await?;
        }
        Ok(())
    }
}

#[cfg(feature = "account")]
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
            AccountEvent::CreateFolder(id, secure_access_key)
            | AccountEvent::ChangeFolderPassword(id, secure_access_key) => {
                writer.write_bytes(id.as_bytes()).await?;
                secure_access_key.encode(&mut *writer).await?;
            }
            AccountEvent::CompactFolder(id) => {
                writer.write_bytes(id.as_bytes()).await?;
            }
            AccountEvent::UpdateFolderName(id, name) => {
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

#[cfg(feature = "account")]
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
                let mut secure_access_key: SecureAccessKey =
                    Default::default();
                secure_access_key.decode(&mut *reader).await?;
                *self = AccountEvent::CreateFolder(id, secure_access_key)
            }
            EventKind::ChangePassword => {
                let id = decode_uuid(&mut *reader).await?;
                let mut secure_access_key: SecureAccessKey =
                    Default::default();
                secure_access_key.decode(&mut *reader).await?;
                *self =
                    AccountEvent::ChangeFolderPassword(id, secure_access_key)
            }
            EventKind::SetVaultName => {
                let id = decode_uuid(&mut *reader).await?;
                let name = reader.read_string().await?;
                *self = AccountEvent::UpdateFolderName(id, name)
            }
            EventKind::CompactVault => {
                let id = decode_uuid(&mut *reader).await?;
                *self = AccountEvent::CompactFolder(id)
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
            FileEvent::CreateFile(folder_id, secret_id, file_name)
            | FileEvent::DeleteFile(folder_id, secret_id, file_name) => {
                writer.write_bytes(folder_id.as_bytes()).await?;
                writer.write_bytes(secret_id.as_bytes()).await?;
                writer.write_string(file_name).await?;
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
                let file_name = reader.read_string().await?;
                *self = FileEvent::CreateFile(folder_id, secret_id, file_name)
            }
            EventKind::DeleteFile => {
                let folder_id = decode_uuid(&mut *reader).await?;
                let secret_id = decode_uuid(&mut *reader).await?;
                let file_name = reader.read_string().await?;
                *self = FileEvent::DeleteFile(folder_id, secret_id, file_name)
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
