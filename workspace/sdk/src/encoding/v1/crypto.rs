use crate::{
    crypto::{
        AeadPack, Cipher, KeyDerivation, Nonce, AES_GCM_256, ARGON_2_ID,
        BALLOON_HASH, X25519, X_CHACHA20_POLY1305, SecureAccessKey,
    },
    encoding::encoding_error,
};

use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use std::io::{Error, ErrorKind, Result};

#[async_trait]
impl Encodable for AeadPack {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        match &self.nonce {
            Nonce::Nonce12(ref bytes) => {
                writer.write_u8(12).await?;
                writer.write_bytes(bytes).await?;
            }
            Nonce::Nonce24(ref bytes) => {
                writer.write_u8(24).await?;
                writer.write_bytes(bytes).await?;
            }
        }
        writer.write_u32(self.ciphertext.len() as u32).await?;
        writer.write_bytes(&self.ciphertext).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for AeadPack {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let nonce_size = reader.read_u8().await?;
        let nonce_buffer = reader.read_bytes(nonce_size as usize).await?;
        match nonce_size {
            12 => {
                self.nonce = Nonce::Nonce12(
                    nonce_buffer
                        .as_slice()
                        .try_into()
                        .map_err(encoding_error)?,
                );
            }
            24 => {
                self.nonce = Nonce::Nonce24(
                    nonce_buffer
                        .as_slice()
                        .try_into()
                        .map_err(encoding_error)?,
                );
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("unknown nonce size {}", nonce_size),
                ));
            }
        }
        let len = reader.read_u32().await?;
        self.ciphertext = reader.read_bytes(len as usize).await?;
        Ok(())
    }
}

#[async_trait]
impl Encodable for Cipher {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let id: u8 = self.into();
        writer.write_u8(id).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for Cipher {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let id = reader.read_u8().await?;
        *self = match id {
            X_CHACHA20_POLY1305 => Cipher::XChaCha20Poly1305,
            AES_GCM_256 => Cipher::AesGcm256,
            X25519 => Cipher::X25519,
            _ => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("unknown cipher {}", id),
                ));
            }
        };
        Ok(())
    }
}

#[async_trait]
impl Encodable for KeyDerivation {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let id: u8 = self.into();
        writer.write_u8(id).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for KeyDerivation {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let id = reader.read_u8().await?;
        *self = match id {
            ARGON_2_ID => KeyDerivation::Argon2Id,
            BALLOON_HASH => KeyDerivation::BalloonHash,
            _ => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("unknown key derivation function {}", id),
                ));
            }
        };
        Ok(())
    }
}

#[async_trait]
impl Encodable for SecureAccessKey {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let id: u8 = match self {
            Self::Password(_, _) => 1,
            Self::Identity(_, _) => 2,
            _ => unreachable!(),
        };
        writer.write_u8(id).await?;

        match self {
            Self::Password(cipher, aead) => {
                cipher.encode(&mut *writer).await?;
                aead.encode(&mut *writer).await?;
            },
            Self::Identity(cipher, aead) => {
                cipher.encode(&mut *writer).await?;
                aead.encode(&mut *writer).await?;
            },
            _ => unreachable!(),
        }

        Ok(())
    }
}

#[async_trait]
impl Decodable for SecureAccessKey {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let id = reader.read_u8().await?;
        match id {
            1 => {
                let mut cipher: Cipher = Default::default();
                cipher.decode(&mut *reader).await?;
                let mut aead: AeadPack = Default::default();
                aead.decode(&mut *reader).await?;
                *self = Self::Password(cipher, aead);
            }  
            2 => {
                let mut cipher: Cipher = Default::default();
                cipher.decode(&mut *reader).await?;
                let mut aead: AeadPack = Default::default();
                aead.decode(&mut *reader).await?;
                *self = Self::Identity(cipher, aead);
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("unknown secure access key variant {}", id),
                ));
            },
        }
        Ok(())
    }
}
