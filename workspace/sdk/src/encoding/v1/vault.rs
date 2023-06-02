use uuid::Uuid;

use crate::{
    commit::CommitHash,
    constants::VAULT_IDENTITY,
    crypto::{AeadPack, SEED_SIZE},
    formats::FileIdentity,
    vault::{
        secret::SecretId, Auth, Contents, Header, Summary, Vault,
        VaultCommit, VaultEntry, VaultFlags, VaultMeta,
    },
    Timestamp,
};

use super::encoding_error;
use async_trait::async_trait;
use binary_stream::tokio::{BinaryReader, BinaryWriter, Decode, Encode};
use std::io::{Error, ErrorKind, Result};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite};

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for VaultMeta {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        self.date_created.encode(&mut *writer).await?;
        writer.write_string(&self.label).await?;
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for VaultMeta {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let mut date_created: Timestamp = Default::default();
        date_created.decode(&mut *reader).await?;
        self.label = reader.read_string().await?;
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for VaultEntry {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        self.0.encode(&mut *writer).await?;
        self.1.encode(&mut *writer).await?;
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for VaultEntry {
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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for VaultCommit {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_bytes(self.0.as_ref()).await?;

        let size_pos = writer.tell().await?;
        writer.write_u32(0).await?;

        self.1.encode(&mut *writer).await?;

        // Encode the data length for lazy iteration
        let row_pos = writer.tell().await?;
        let row_len = row_pos - (size_pos + 4);
        writer.seek(size_pos).await?;
        writer.write_u32(row_len as u32).await?;
        writer.seek(row_pos).await?;

        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for VaultCommit {
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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for Auth {
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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for Auth {
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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for Summary {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_u16(self.version).await?;
        self.algorithm.encode(&mut *writer).await?;
        self.kdf.encode(&mut *writer).await?;
        writer.write_bytes(self.id.as_bytes()).await?;
        writer.write_string(&self.name).await?;
        writer.write_u64(self.flags.bits()).await?;
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for Summary {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        self.version = reader.read_u16().await?;
        self.algorithm.decode(&mut *reader).await?;
        self.kdf.decode(&mut *reader).await?;

        let uuid: [u8; 16] = reader
            .read_bytes(16)
            .await?
            .as_slice()
            .try_into()
            .map_err(encoding_error)?;

        self.id = Uuid::from_bytes(uuid);
        self.name = reader.read_string().await?;
        self.flags = VaultFlags::from_bits(reader.read_u64().await?)
            .ok_or(crate::Error::InvalidVaultFlags)
            .map_err(encoding_error)?;
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for Header {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        FileIdentity::write_identity(&mut *writer, &VAULT_IDENTITY)
            .await
            .map_err(encoding_error)?;

        let size_pos = writer.tell().await?;
        writer.write_u32(0).await?;

        self.summary.encode(&mut *writer).await?;

        writer.write_bool(self.meta.is_some()).await?;
        if let Some(meta) = &self.meta {
            meta.encode(&mut *writer).await?;
        }

        self.auth.encode(&mut *writer).await?;

        // Backtrack to size_pos and write new length
        let header_pos = writer.tell().await?;
        let header_len = header_pos - (size_pos + 4);

        writer.seek(size_pos).await?;
        writer.write_u32(header_len as u32).await?;
        writer.seek(header_pos).await?;

        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for Header {
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
        Ok(())
    }
}

impl Contents {
    /// Encode a single row into a serializer.
    pub async fn encode_row<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        writer: &mut BinaryWriter<W>,
        key: &SecretId,
        row: &VaultCommit,
    ) -> Result<()> {
        let size_pos = writer.tell().await?;
        writer.write_u32(0).await?;

        writer.write_bytes(key.as_bytes()).await?;
        row.encode(&mut *writer).await?;

        // Backtrack to size_pos and write new length
        let row_pos = writer.tell().await?;
        let row_len = row_pos - (size_pos + 4);
        writer.seek(size_pos).await?;
        writer.write_u32(row_len as u32).await?;
        writer.seek(row_pos).await?;

        // Write out the row len at the end of the record too
        // so we can support double ended iteration
        writer.write_u32(row_len as u32).await?;

        Ok(())
    }

    /// Decode a single row from a deserializer.
    pub async fn decode_row<R: AsyncRead + AsyncSeek + Unpin + Send>(
        reader: &mut BinaryReader<R>,
    ) -> Result<(SecretId, VaultCommit)> {
        // Read in the row length
        let _ = reader.read_u32().await?;

        let uuid: [u8; 16] = reader
            .read_bytes(16)
            .await?
            .as_slice()
            .try_into()
            .map_err(encoding_error)?;
        let uuid = Uuid::from_bytes(uuid);

        let mut row: VaultCommit = Default::default();
        row.decode(&mut *reader).await?;

        // Read in the row length suffix
        let _ = reader.read_u32().await?;

        Ok((uuid, row))
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for Contents {
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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for Contents {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let mut pos = reader.tell().await?;
        let len = reader.len().await?;
        while pos < len {
            let (uuid, value) = Contents::decode_row(reader).await?;
            self.data.insert(uuid, value);
            pos = reader.tell().await?;
        }

        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for Vault {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        self.header.encode(writer).await?;
        self.contents.encode(writer).await?;
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for Vault {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        self.header.decode(reader).await?;
        self.contents.decode(reader).await?;
        Ok(())
    }
}
