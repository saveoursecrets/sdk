//! Constants for supported symmetric ciphers.
use crate::Error;
use binary_stream::{
    BinaryError, BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};
use std::{
    convert::AsRef,
    fmt,
    io::{Read, Seek, Write},
    str::FromStr,
};

/// Extended ChaCha20 Poly1305 cipher.
pub const X_CHACHA20_POLY1305: u8 = 0x01;

/// AES-GCM 256 cipher.
pub const AES_GCM_256: u8 = 0x02;

/// Supported algorithms.
pub const ALGORITHMS: [u8; 2] = [X_CHACHA20_POLY1305, AES_GCM_256];

/// Supported cipher algorithms.
#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone)]
pub enum Algorithm {
    /// Algorithm for XChaCha20Poly1305 encryption.
    XChaCha20Poly1305(u8),
    /// Algorithm for AES-GCM 256 bit encryption.
    AesGcm256(u8),
}

impl Algorithm {
    /// The AES-GCM 256 bit algorithm.
    pub fn aes() -> Self {
        Self::AesGcm256(AES_GCM_256)
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", {
            match self {
                Self::XChaCha20Poly1305(_) => "X_CHACHA20_POLY1305",
                Self::AesGcm256(_) => "AES_GCM_256",
            }
        })
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "x_chacha20_poly1305" => Ok(Self::default()),
            "aes_gcm_256" => Ok(Self::aes()),
            _ => Err(Error::InvalidAlgorithm(s.to_string())),
        }
    }
}

impl From<Algorithm> for u8 {
    fn from(value: Algorithm) -> Self {
        match value {
            Algorithm::XChaCha20Poly1305(id) => id,
            Algorithm::AesGcm256(id) => id,
        }
    }
}

impl TryFrom<u8> for Algorithm {
    type Error = Error;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            X_CHACHA20_POLY1305 => {
                Ok(Algorithm::XChaCha20Poly1305(X_CHACHA20_POLY1305))
            }
            AES_GCM_256 => Ok(Algorithm::AesGcm256(AES_GCM_256)),
            _ => Err(Error::InvalidAlgorithm(value.to_string())),
        }
    }
}

impl AsRef<u8> for Algorithm {
    fn as_ref(&self) -> &u8 {
        match self {
            Algorithm::XChaCha20Poly1305(ref id) => id,
            Algorithm::AesGcm256(ref id) => id,
        }
    }
}

impl Default for Algorithm {
    fn default() -> Self {
        Self::XChaCha20Poly1305(X_CHACHA20_POLY1305)
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
            X_CHACHA20_POLY1305 => Algorithm::XChaCha20Poly1305(id),
            AES_GCM_256 => Algorithm::AesGcm256(id),
            _ => {
                return Err(BinaryError::Boxed(Box::from(
                    Error::UnknownAlgorithm(id),
                )));
            }
        };
        Ok(())
    }
}
