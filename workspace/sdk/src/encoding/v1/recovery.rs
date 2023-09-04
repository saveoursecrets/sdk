use secrecy::{ExposeSecret, SecretString};
use std::io::Result;
use uuid::Uuid;

use crate::{
    crypto::SEED_SIZE,
    encoding::encoding_error,
    recovery::{RecoveryData, RecoveryOptions, RecoveryPack},
};

use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};

#[async_trait]
impl Encodable for RecoveryData {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_u32(self.vaults().len() as u32).await?;
        for (k, v) in self.vaults() {
            writer.write_bytes(k.as_bytes()).await?;
            writer.write_string(v.expose_secret()).await?;
        }

        Ok(())
    }
}

#[async_trait]
impl Decodable for RecoveryData {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let len = reader.read_u32().await?;
        for _ in 0..len {
            let uuid: [u8; 16] = reader
                .read_bytes(16)
                .await?
                .as_slice()
                .try_into()
                .map_err(encoding_error)?;
            let id = Uuid::from_bytes(uuid);
            let password = SecretString::new(reader.read_string().await?);
            self.vaults_mut().insert(id, password);
        }
        Ok(())
    }
}

#[async_trait]
impl Encodable for RecoveryOptions {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_u8(self.limit).await?;
        writer.write_u8(self.threshold).await?;
        self.cipher.encode(&mut *writer).await?;
        self.kdf.encode(&mut *writer).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for RecoveryOptions {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        self.limit = reader.read_u8().await?;
        self.threshold = reader.read_u8().await?;
        self.cipher.decode(&mut *reader).await?;
        self.kdf.decode(&mut *reader).await?;
        Ok(())
    }
}

#[async_trait]
impl Encodable for RecoveryPack {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_bytes(self.id.as_bytes()).await?;
        writer.write_u32(self.vaults.len() as u32).await?;
        for id in &self.vaults {
            writer.write_bytes(id.as_bytes()).await?;
        }
        self.options.encode(&mut *writer).await?;
        writer.write_string(&self.salt).await?;
        writer.write_bytes(&self.seed).await?;
        self.data.encode(&mut *writer).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for RecoveryPack {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let uuid: [u8; 16] = reader
            .read_bytes(16)
            .await?
            .as_slice()
            .try_into()
            .map_err(encoding_error)?;
        self.id = Uuid::from_bytes(uuid);
        
        let len = reader.read_u32().await? as usize;
        for _ in 0..len {
            let uuid: [u8; 16] = reader
                .read_bytes(16)
                .await?
                .as_slice()
                .try_into()
                .map_err(encoding_error)?;
            self.vaults.push(Uuid::from_bytes(uuid));
        }

        self.options.decode(&mut *reader).await?;
        self.salt = reader.read_string().await?;
        self.seed = reader
            .read_bytes(SEED_SIZE)
            .await?
            .as_slice()
            .try_into()
            .map_err(encoding_error)?;
        self.data.decode(&mut *reader).await?;
        Ok(())
    }
}
