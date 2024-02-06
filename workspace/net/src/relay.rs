//! Relay packet encoding.
use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use std::io::{Error, ErrorKind, Result};

/// Message sent between devices being paired.
#[derive(Default)]
pub struct RelayPacket {
    /// Packet header data.
    pub header: RelayHeader,
    /// Payload for the recipient.
    pub payload: RelayPayload,
}

/// Header of a pairing packet.
#[derive(Default)]
pub struct RelayHeader {
    /// Public key of the recipient.
    pub to_public_key: Vec<u8>,
    /// Public key of the sender.
    pub from_public_key: Vec<u8>,
}

/// Packet for pairing communication.
#[derive(Default)]
pub enum RelayPayload {
    #[default]
    #[doc(hidden)]
    Noop,
    /// Handshake packet.
    Handshake(usize, Vec<u8>),
    /// Encrypted transport packet.
    Transport(usize, Vec<u8>),
}

/// Length-prefixed message body.
#[derive(Default)]
pub struct RelayBody {
    /// Length of the body buffer.
    length: u16,
    /// Buffer of the message content.
    buffer: Vec<u8>,
}

impl From<Vec<u8>> for RelayBody {
    fn from(buffer: Vec<u8>) -> Self {
        Self {
            length: buffer.len() as u16,
            buffer,
        }
    }
}

impl AsRef<[u8]> for RelayBody {
    fn as_ref(&self) -> &[u8] {
        &self.buffer
    }
}

#[async_trait]
impl Encodable for RelayPacket {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        self.header.encode(&mut *writer).await?;
        match &self.payload {
            RelayPayload::Noop => panic!("attempt to encode a noop"),
            RelayPayload::Handshake(len, buf) => {
                writer.write_u8(1).await?;
                writer.write_u16(*len as u16).await?;
                writer.write_bytes(buf).await?;
            }
            RelayPayload::Transport(len, buf) => {
                writer.write_u8(2).await?;
                writer.write_u16(*len as u16).await?;
                writer.write_bytes(buf).await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Decodable for RelayPacket {
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
                self.payload = RelayPayload::Handshake(len as usize, buf);
            }
            2 => {
                let len = reader.read_u16().await?;
                let buf = reader.read_bytes(len as usize).await?;
                self.payload = RelayPayload::Transport(len as usize, buf);
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
impl Encodable for RelayHeader {
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
impl Decodable for RelayHeader {
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

#[async_trait]
impl Encodable for RelayBody {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_u16(self.buffer.len() as u16).await?;
        writer.write_bytes(&self.buffer).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for RelayBody {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        self.length = reader.read_u16().await?;
        self.buffer = reader.read_bytes(self.length as usize).await?;
        Ok(())
    }
}
