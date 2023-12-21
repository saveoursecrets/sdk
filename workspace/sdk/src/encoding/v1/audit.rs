use crate::{
    audit::{AuditData, AuditEvent, AuditLogFile, AuditLogFlags},
    encoding::{decode_uuid, encoding_error},
    Timestamp,
};

use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use std::io::{Error, ErrorKind, Result, SeekFrom};

use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};

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
        if flags.contains(AuditLogFlags::DATA) {
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
        if let Some(flags) = AuditLogFlags::from_bits(bits) {
            if flags.contains(AuditLogFlags::DATA) {
                if flags.contains(AuditLogFlags::DATA_VAULT) {
                    let vault_id = decode_uuid(&mut *reader).await?;
                    if !flags.contains(AuditLogFlags::DATA_SECRET) {
                        self.data = Some(AuditData::Vault(vault_id));
                    } else {
                        let secret_id = decode_uuid(&mut *reader).await?;
                        self.data =
                            Some(AuditData::Secret(vault_id, secret_id));
                    }
                } else if flags.contains(AuditLogFlags::MOVE_SECRET) {
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
