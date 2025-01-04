use crate::{
    Auth, Contents, Header, SharedAccess, Summary, Vault, VaultCommit,
    VaultFlags, VaultMeta,
};
use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use sos_core::{
    constants::VAULT_IDENTITY,
    crypto::{AeadPack, SEED_SIZE},
    encoding::{decode_uuid, encoding_error},
    file_identity::FileIdentity,
    SecretId, UtcDateTime,
};
use std::io::{Error, ErrorKind, Result, SeekFrom};

#[async_trait]
impl Encodable for VaultMeta {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        self.date_created.encode(&mut *writer).await?;
        writer.write_string(&self.description).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for VaultMeta {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let mut date_created: UtcDateTime = Default::default();
        date_created.decode(&mut *reader).await?;
        self.description = reader.read_string().await?;
        Ok(())
    }
}

#[async_trait]
impl Encodable for Auth {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_bool(self.salt.is_some()).await?;
        if let Some(salt) = &self.salt {
            writer.write_string(salt).await?;
        }
        writer.write_bool(self.seed.is_some()).await?;
        if let Some(seed) = &self.seed {
            writer.write_bytes(seed).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Decodable for Auth {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let has_salt = reader.read_bool().await?;
        if has_salt {
            self.salt = Some(reader.read_string().await?);
        }
        let has_seed = reader.read_bool().await?;
        if has_seed {
            self.seed = Some(
                reader
                    .read_bytes(SEED_SIZE)
                    .await?
                    .as_slice()
                    .try_into()
                    .map_err(encoding_error)?,
            );
        }
        Ok(())
    }
}

#[async_trait]
impl Encodable for Summary {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_u16(self.version).await?;
        self.cipher.encode(&mut *writer).await?;
        self.kdf.encode(&mut *writer).await?;
        writer.write_bytes(self.id.as_bytes()).await?;
        writer.write_string(&self.name).await?;
        writer.write_u64(self.flags.bits()).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for Summary {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        self.version = reader.read_u16().await?;
        self.cipher.decode(&mut *reader).await?;
        self.kdf.decode(&mut *reader).await?;
        self.id = decode_uuid(&mut *reader).await?;
        self.name = reader.read_string().await?;
        self.flags = VaultFlags::from_bits(reader.read_u64().await?)
            .ok_or(crate::Error::InvalidVaultFlags)
            .map_err(encoding_error)?;
        Ok(())
    }
}

#[async_trait]
impl Encodable for Header {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_bytes(&VAULT_IDENTITY).await?;

        let size_pos = writer.stream_position().await?;
        writer.write_u32(0).await?;

        self.summary.encode(&mut *writer).await?;

        writer.write_bool(self.meta.is_some()).await?;
        if let Some(meta) = &self.meta {
            meta.encode(&mut *writer).await?;
        }

        self.auth.encode(&mut *writer).await?;
        self.shared_access.encode(&mut *writer).await?;

        // Backtrack to size_pos and write new length
        let header_pos = writer.stream_position().await?;
        let header_len = header_pos - (size_pos + 4);

        writer.seek(SeekFrom::Start(size_pos)).await?;
        writer.write_u32(header_len as u32).await?;
        writer.seek(SeekFrom::Start(header_pos)).await?;

        Ok(())
    }
}

#[async_trait]
impl Decodable for Header {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        FileIdentity::read_identity(&mut *reader, &VAULT_IDENTITY)
            .await
            .map_err(|_| {
                Error::new(ErrorKind::Other, "bad vault identity bytes")
            })?;

        // Read in the header length
        let _ = reader.read_u32().await?;

        self.summary.decode(&mut *reader).await?;

        let has_meta = reader.read_bool().await?;
        if has_meta {
            self.meta = Some(Default::default());
            if let Some(meta) = self.meta.as_mut() {
                meta.decode(&mut *reader).await?;
            }
        }

        self.auth.decode(&mut *reader).await?;
        self.shared_access.decode(&mut *reader).await?;

        Ok(())
    }
}

#[async_trait]
impl Encodable for SharedAccess {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        match self {
            SharedAccess::WriteAccess(recipients) => {
                writer.write_u8(1).await?;
                writer.write_u16(recipients.len() as u16).await?;
                for recipient in recipients {
                    writer.write_string(recipient).await?;
                }
            }
            SharedAccess::ReadOnly(aead) => {
                writer.write_u8(2).await?;
                aead.encode(writer).await?;
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Decodable for SharedAccess {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let id = reader.read_u8().await?;

        match id {
            1 => {
                let mut recipients = Vec::new();
                let length = reader.read_u16().await?;
                for _ in 0..length {
                    let recipient = reader.read_string().await?;
                    let _: age::x25519::Recipient =
                        recipient.parse().map_err(|e: &str| {
                            Error::new(
                                ErrorKind::Other,
                                crate::Error::InvalidX25519Identity(
                                    e.to_owned(),
                                ),
                            )
                        })?;
                    recipients.push(recipient);
                }
                *self = SharedAccess::WriteAccess(recipients);
            }
            2 => {
                let mut aead: AeadPack = Default::default();
                aead.decode(reader).await?;
                *self = SharedAccess::ReadOnly(aead);
            }
            _ => {
                return Err(encoding_error(
                    crate::Error::UnknownSharedAccessKind(id),
                ));
            }
        }

        Ok(())
    }
}

impl Contents {
    /// Encodable a single row into a serializer.
    pub async fn encode_row<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        writer: &mut BinaryWriter<W>,
        key: &SecretId,
        row: &VaultCommit,
    ) -> Result<()> {
        let size_pos = writer.stream_position().await?;
        writer.write_u32(0).await?;

        writer.write_bytes(key.as_bytes()).await?;

        row.encode(&mut *writer).await?;

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

    /// Decodable a single row from a deserializer.
    pub async fn decode_row<R: AsyncRead + AsyncSeek + Unpin + Send>(
        reader: &mut BinaryReader<R>,
    ) -> Result<(SecretId, VaultCommit)> {
        // Read in the row length
        let _ = reader.read_u32().await?;

        let uuid = decode_uuid(&mut *reader).await?;

        let mut row: VaultCommit = Default::default();
        row.decode(&mut *reader).await?;

        // Read in the row length suffix
        let _ = reader.read_u32().await?;

        Ok((uuid, row))
    }
}

#[async_trait]
impl Encodable for Contents {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        for (key, row) in &self.data {
            Contents::encode_row(writer, key, row).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Decodable for Contents {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let mut pos = reader.stream_position().await?;
        let len = reader.len().await?;
        while pos < len {
            let (uuid, value) = Contents::decode_row(reader).await?;
            self.data.insert(uuid, value);
            pos = reader.stream_position().await?;
        }

        Ok(())
    }
}

#[async_trait]
impl Encodable for Vault {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        self.header.encode(writer).await?;
        self.contents.encode(writer).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for Vault {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        self.header.decode(reader).await?;
        self.contents.decode(reader).await?;
        Ok(())
    }
}
