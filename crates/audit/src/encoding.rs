use crate::{AuditData, AuditEvent, AuditLogFlags};
use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use sos_core::{
    encoding::{decode_uuid, encoding_error},
    UtcDateTime,
};
use std::io::{Error, ErrorKind, Result};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite};

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
        // Account identifier - by whom
        writer.write_bytes(self.account_id.as_ref()).await?;
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
        let mut timestamp: UtcDateTime = Default::default();
        timestamp.decode(&mut *reader).await?;
        self.time = timestamp;
        // EventKind - the what
        self.event_kind.decode(&mut *reader).await?;
        // Account identifier - by whom
        let address = reader.read_bytes(20).await?;
        let address: [u8; 20] =
            address.as_slice().try_into().map_err(encoding_error)?;
        self.account_id = address.into();
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
            AuditData::Device(public_key) => {
                writer.write_bytes(public_key.as_ref()).await?;
            }
        }
        Ok(())
    }
}
