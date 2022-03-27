//! Utilities for computing the address for a public key.
use crate::{Result, Error};
use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, DecompressPoint, ScalarCore},
    AffinePoint, EncodedPoint, FieldBytes, Scalar, Secp256k1,
};
use sha3::{Digest, Keccak256};
use subtle::Choice;
use std::str::FromStr;
use serde::{Serialize, Deserialize};

/// Represents a public address that may be converted to and from
/// a string.
///
/// It must begin with 0x and be followed with 20 bytes hex-encoded.
#[derive(Debug, Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
#[serde(try_from = "String", into = "String")]
pub struct AddressStr([u8; 20]);

impl AddressStr {
    /// Convert to a string.
    pub fn to_string(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

impl FromStr for AddressStr {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if !s.starts_with("0x") {
            return Err(Error::BadAddressPrefix)
        }
        let bytes = hex::decode(&s[2..])?;
        let buffer: [u8; 20] = bytes.as_slice().try_into()?;
        Ok(AddressStr(buffer))
    }
}

impl Into<String> for AddressStr {
    fn into(self) -> String {
        self.to_string()
    }
}

impl TryFrom<String> for AddressStr {
    type Error = Error;
    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        <AddressStr as FromStr>::from_str(&value)
    }
}

// FIXME: handle panics / unwrap here!

/// Decompress the bytes for a compressed public key into a point on the secp256k1 curve.
fn decompress(compressed_bytes: &[u8; 33]) -> Result<EncodedPoint> {
    let y_is_odd = if compressed_bytes[0] == 3 {
        Choice::from(1)
    } else {
        Choice::from(0)
    };
    let x: &[u8; 32] = &compressed_bytes[1..].try_into()?;
    let scalar_core = ScalarCore::<Secp256k1>::from_be_slice(x)?;
    let scalar = Scalar::from(scalar_core);
    let x_bytes = FieldBytes::from(scalar);
    let point = AffinePoint::decompress(&x_bytes, y_is_odd).unwrap();
    let point = point.to_encoded_point(false);
    Ok(point)
}

/// Compute the public address for a compressed public key.
pub fn address_compressed(compressed_bytes: &[u8; 33]) -> Result<String> {
    let decompressed = decompress(compressed_bytes)?;
    let x: [u8; 32] = *decompressed.x().unwrap().as_ref();
    let y: [u8; 32] = *decompressed.y().unwrap().as_ref();
    let bytes: [u8; 64] = [x, y].concat().as_slice().try_into()?;
    address(&bytes)
}

/// Compute the public address for a decompressed public key.
pub fn address_decompressed(bytes: &[u8; 65]) -> Result<String> {
    let bytes: [u8; 64] = bytes[1..].try_into()?;
    address(&bytes)
}

/// Compute the public address for the bytes representing the x / y coordinate pair.
pub fn address(bytes: &[u8; 64]) -> Result<String> {
    let digest = Keccak256::digest(bytes);
    let final_bytes = &digest[12..];
    Ok(format!("0x{}", hex::encode(&final_bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    const COMPRESSED_PUBLIC_KEY: &str =
        "025f37d20e5b18909361e0ead7ed17c69b417bee70746c9e9c2bcb1394d921d4ae";
    const COMPRESSED_ADDRESS: &str = "0xd09d3103ccabfb769edc3e9b01500ca7241d470a";

    const PUBLIC_KEY: [u8; 33] = [
        3, 191, 74, 169, 115, 14, 12, 199, 99, 221, 125, 5, 13, 247, 115, 157, 30, 185, 140, 2, 20,
        153, 10, 245, 177, 145, 111, 188, 103, 92, 61, 227, 121,
    ];

    #[test]
    fn decompress_test() -> Result<()> {
        let decompressed = decompress(&PUBLIC_KEY)?;
        let x = decompressed.x();
        let y = decompressed.y();
        assert!(x.is_some());
        assert!(y.is_some());
        Ok(())
    }

    #[test]
    fn address_test() -> Result<()> {
        let compressed_bytes = hex::decode(COMPRESSED_PUBLIC_KEY)?;
        let mut bytes: [u8; 33] = [0; 33];
        bytes.copy_from_slice(&compressed_bytes[..]);
        let address = address_compressed(&bytes)?;
        assert_eq!(COMPRESSED_ADDRESS, address);
        Ok(())
    }
}
