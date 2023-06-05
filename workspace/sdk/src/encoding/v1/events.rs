use std::borrow::Cow;

use crate::{
    commit::CommitHash,
    crypto::AeadPack,
    events::{
        AuditData, AuditEvent, AuditLogFile, EventKind, EventRecord,
        LogFlags, WriteEvent,
    },
    formats::{EventLogFileRecord, FileRecord, VaultRecord},
    vault::{secret::SecretId, VaultCommit},
    Timestamp,
};

use std::io::{Error, ErrorKind, Result, SeekFrom};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};

use super::encoding_error;
use async_trait::async_trait;
use binary_stream::futures::{BinaryReader, BinaryWriter, Decode, Encode};

use uuid::Uuid;

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for EventKind {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let value: u16 = self.into();
        writer.write_u16(value).await?;
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for EventKind {
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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for EventRecord {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        // Prepare the bytes for the row length
        let size_pos = writer.tell().await?;
        writer.write_u32(0).await?;

        // Encode the time component
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
        let row_pos = writer.tell().await?;
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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for EventRecord {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        // Read in the row length
        let _ = reader.read_u32().await?;

        // Decode the time component
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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for AuditEvent {
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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for AuditEvent {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        // Context bit flags
        let bits = reader.read_u16().await?;
        // Time - the when
        let mut timestamp: Timestamp = Default::default();
        timestamp.decode(&mut *reader).await?;
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
                    let vault_id: [u8; 16] = reader
                        .read_bytes(16)
                        .await?
                        .as_slice()
                        .try_into()
                        .map_err(encoding_error)?;
                    if !flags.contains(LogFlags::DATA_SECRET) {
                        self.data = Some(AuditData::Vault(Uuid::from_bytes(
                            vault_id,
                        )));
                    } else {
                        let secret_id: [u8; 16] = reader
                            .read_bytes(16)
                            .await?
                            .as_slice()
                            .try_into()
                            .map_err(encoding_error)?;
                        self.data = Some(AuditData::Secret(
                            Uuid::from_bytes(vault_id),
                            Uuid::from_bytes(secret_id),
                        ));
                    }
                } else if flags.contains(LogFlags::MOVE_SECRET) {
                    let from_vault_id: [u8; 16] = reader
                        .read_bytes(16)
                        .await?
                        .as_slice()
                        .try_into()
                        .map_err(encoding_error)?;

                    let from_secret_id: [u8; 16] = reader
                        .read_bytes(16)
                        .await?
                        .as_slice()
                        .try_into()
                        .map_err(encoding_error)?;

                    let to_vault_id: [u8; 16] = reader
                        .read_bytes(16)
                        .await?
                        .as_slice()
                        .try_into()
                        .map_err(encoding_error)?;

                    let to_secret_id: [u8; 16] = reader
                        .read_bytes(16)
                        .await?
                        .as_slice()
                        .try_into()
                        .map_err(encoding_error)?;

                    self.data = Some(AuditData::MoveSecret {
                        from_vault_id: Uuid::from_bytes(from_vault_id),
                        from_secret_id: Uuid::from_bytes(from_secret_id),
                        to_vault_id: Uuid::from_bytes(to_vault_id),
                        to_secret_id: Uuid::from_bytes(to_secret_id),
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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for AuditData {
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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<'a> Encode for WriteEvent<'a> {
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
                writer.write_u32(vault.as_ref().len() as u32).await?;
                writer.write_bytes(vault.as_ref()).await?;
            }
            WriteEvent::DeleteVault => {}
            WriteEvent::SetVaultName(name) => {
                writer.write_string(name).await?;
            }
            WriteEvent::SetVaultMeta(meta) => {
                writer.write_bool(meta.is_some()).await?;
                if let Some(meta) = meta.as_ref() {
                    meta.encode(&mut *writer).await?;
                }
            }
            WriteEvent::CreateSecret(uuid, value) => {
                writer.write_bytes(uuid.as_bytes()).await?;
                value.as_ref().encode(&mut *writer).await?;
            }
            WriteEvent::UpdateSecret(uuid, value) => {
                writer.write_bytes(uuid.as_bytes()).await?;
                value.as_ref().encode(&mut *writer).await?;
            }
            WriteEvent::DeleteSecret(uuid) => {
                writer.write_bytes(uuid.as_bytes()).await?;
            }
        }
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<'a> Decode for WriteEvent<'a> {
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
                *self = WriteEvent::CreateVault(Cow::Owned(buffer))
            }
            EventKind::UpdateVault => {
                let length = reader.read_u32().await?;
                let buffer = reader.read_bytes(length as usize).await?;
                *self = WriteEvent::UpdateVault(Cow::Owned(buffer))
            }
            EventKind::DeleteVault => {
                *self = WriteEvent::DeleteVault;
            }
            EventKind::SetVaultName => {
                let name = reader.read_string().await?;
                *self = WriteEvent::SetVaultName(Cow::Owned(name));
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
                *self = WriteEvent::SetVaultMeta(Cow::Owned(aead_pack));
            }
            EventKind::CreateSecret => {
                let id = SecretId::from_bytes(
                    reader
                        .read_bytes(16)
                        .await?
                        .as_slice()
                        .try_into()
                        .map_err(encoding_error)?,
                );
                let mut commit: VaultCommit = Default::default();
                commit.decode(&mut *reader).await?;
                *self = WriteEvent::CreateSecret(id, Cow::Owned(commit));
            }
            EventKind::UpdateSecret => {
                let id = SecretId::from_bytes(
                    reader
                        .read_bytes(16)
                        .await?
                        .as_slice()
                        .try_into()
                        .map_err(encoding_error)?,
                );
                let mut commit: VaultCommit = Default::default();
                commit.decode(&mut *reader).await?;
                *self = WriteEvent::UpdateSecret(id, Cow::Owned(commit));
            }
            EventKind::DeleteSecret => {
                let id = SecretId::from_bytes(
                    reader
                        .read_bytes(16)
                        .await?
                        .as_slice()
                        .try_into()
                        .map_err(encoding_error)?,
                );
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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for EventLogFileRecord {
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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for FileRecord {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        _reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for VaultRecord {
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
    /// Encode an audit log event record.
    pub(crate) async fn encode_row<
        W: AsyncWrite + AsyncSeek + Unpin + Send,
    >(
        writer: &mut BinaryWriter<W>,
        event: AuditEvent,
    ) -> Result<()> {
        // Set up the leading row length
        let size_pos = writer.tell().await?;
        writer.write_u32(0).await?;

        // Encode the event data for the row
        event.encode(&mut *writer).await?;

        // Backtrack to size_pos and write new length
        let row_pos = writer.tell().await?;
        let row_len = row_pos - (size_pos + 4);
        writer.seek(SeekFrom::Start(size_pos)).await?;
        writer.write_u32(row_len as u32).await?;
        writer.seek(SeekFrom::Start(row_pos)).await?;

        // Write out the row len at the end of the record too
        // so we can support double ended iteration
        writer.write_u32(row_len as u32).await?;

        Ok(())
    }

    /// Decode an audit log event record.
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
