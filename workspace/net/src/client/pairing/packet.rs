//! Pairing packet encoding.
use crate::sdk::device::TrustedDevice;
use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use serde::{Deserialize, Serialize};
use std::io::{Error, ErrorKind, Result, SeekFrom};

/// Message sent between devices being paired.
#[derive(Default)]
pub(super) struct PairingPacket {
    /// Packet header data.
    pub header: PairingHeader,
    /// Payload for the recipient.
    pub payload: PairingPayload,
}

/// Header of a pairing packet.
#[derive(Default)]
pub(super) struct PairingHeader {
    /// Public key of the recipient.
    pub to_public_key: Vec<u8>,
    /// Public key of the sender.
    pub from_public_key: Vec<u8>,
}

/// Packet for pairing communication.
#[derive(Default)]
pub(super) enum PairingPayload {
    #[default]
    Noop,
    /// Handshake packet.
    Handshake(usize, Vec<u8>),
    /// Encrypted transport packet.
    Transport(usize, Vec<u8>),
}

/// Pairing message.
#[derive(Serialize, Deserialize)]
pub(super) enum PairingMessage {
    /// Request sent from the accept side to the
    /// offering side once the noise protocol handshake
    /// has completed.
    Request(TrustedDevice),
    /// Confirmation from the offering side to the
    /// accepting side is the account signing key.
    Confirm([u8; 32]),
    /// Offer side generated an error whilst
    /// adding the device to the list of trusted devices.
    Error(String),
}

#[async_trait]
impl Encodable for PairingPacket {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        self.header.encode(&mut *writer).await?;
        match &self.payload {
            PairingPayload::Noop => panic!("attempt to encode a noop"),
            PairingPayload::Handshake(len, buf) => {
                writer.write_u8(1).await?;
                writer.write_u16(*len as u16).await?;
                writer.write_bytes(buf).await?;
            }
            PairingPayload::Transport(len, buf) => {
                writer.write_u8(2).await?;
                writer.write_u16(*len as u16).await?;
                writer.write_bytes(buf).await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Decodable for PairingPacket {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        self.header.decode(&mut *reader).await?;
        let op = reader.read_u8().await?;
        match op {
            1 => {
                let len = reader.read_u16().await?;
                let buf = reader.read_bytes(len as usize).await?;
                self.payload = PairingPayload::Handshake(len as usize, buf);
            }
            2 => {
                let len = reader.read_u16().await?;
                let buf = reader.read_bytes(len as usize).await?;
                self.payload = PairingPayload::Transport(len as usize, buf);
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("unknown pairing packet payload type {}", op),
                ));
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Encodable for PairingHeader {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_u16(self.to_public_key.len() as u16).await?;
        writer.write_bytes(&self.to_public_key).await?;
        writer.write_u16(self.from_public_key.len() as u16).await?;
        writer.write_bytes(&self.from_public_key).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for PairingHeader {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let len = reader.read_u16().await?;
        self.to_public_key = reader.read_bytes(len as usize).await?;
        let len = reader.read_u16().await?;
        self.from_public_key = reader.read_bytes(len as usize).await?;
        Ok(())
    }
}
