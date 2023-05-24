use crate::{
    crypto::{AeadPack, Algorithm, Nonce},
    Error,
};
use binary_stream::{
    BinaryError, BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};

use std::io::{Read, Seek, Write};

impl Encode for AeadPack {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        match &self.nonce {
            Nonce::Nonce12(ref bytes) => {
                writer.write_u8(12)?;
                writer.write_bytes(bytes)?;
            }
            Nonce::Nonce24(ref bytes) => {
                writer.write_u8(24)?;
                writer.write_bytes(bytes)?;
            }
        }
        writer.write_u32(self.ciphertext.len() as u32)?;
        writer.write_bytes(&self.ciphertext)?;
        Ok(())
    }
}

impl Decode for AeadPack {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        let nonce_size = reader.read_u8()?;
        let nonce_buffer = reader.read_bytes(nonce_size as usize)?;
        match nonce_size {
            12 => {
                self.nonce =
                    Nonce::Nonce12(nonce_buffer.as_slice().try_into()?)
            }
            24 => {
                self.nonce =
                    Nonce::Nonce24(nonce_buffer.as_slice().try_into()?)
            }
            _ => {
                return Err(BinaryError::Boxed(Box::from(
                    Error::UnknownNonceSize(nonce_size),
                )));
            }
        }
        let len = reader.read_u32()?;
        self.ciphertext = reader.read_bytes(len as usize)?;
        Ok(())
    }
}

impl Encode for Algorithm {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        writer.write_u8(*self.as_ref())?;
        Ok(())
    }
}

impl Decode for Algorithm {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        let id = reader.read_u8()?;
        *self = match id {
            _X_CHACHA20_POLY1305 => Algorithm::XChaCha20Poly1305(id),
            _AES_GCM_256 => Algorithm::AesGcm256(id),
            _ => {
                return Err(BinaryError::Boxed(Box::from(
                    Error::UnknownAlgorithm(id),
                )));
            }
        };
        Ok(())
    }
}
