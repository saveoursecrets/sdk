use crate::crypto::{
    AeadPack, Cipher, KeyDerivation, Nonce, AES_GCM_256, ARGON_2_ID,
    BALLOON_HASH, X25519, X_CHACHA20_POLY1305,
};

use std::io::{Error, ErrorKind, Result};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite};

use super::encoding_error;
use async_trait::async_trait;
use binary_stream::tokio::{BinaryReader, BinaryWriter, Decode, Encode};

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for AeadPack {
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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for AeadPack {
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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for Cipher {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let id: u8 = self.into();
        writer.write_u8(id).await?;

        match self {
            Cipher::X25519(recipients) => {
                writer.write_u16(recipients.len() as u16).await?;
                for recipient in recipients {
                    writer.write_string(recipient.to_string()).await?;
                }
            }
            _ => {}
        }

        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for Cipher {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let id = reader.read_u8().await?;
        *self = match id {
            X_CHACHA20_POLY1305 => Cipher::XChaCha20Poly1305,
            AES_GCM_256 => Cipher::AesGcm256,
            X25519 => {
                let mut recipients: Vec<age::x25519::Recipient> = Vec::new();
                let length = reader.read_u16().await?;
                for _ in 0..length {
                    let recipient = reader.read_string().await?;
                    recipients.push(
                        recipient
                            .parse()
                            .map_err(|e| Error::new(ErrorKind::Other, e))?,
                    );
                }
                Cipher::X25519(recipients)
            }
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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for KeyDerivation {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let id: u8 = self.into();
        writer.write_u8(id).await?;
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for KeyDerivation {
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
