//! Ethereum style address.
use crate::{Error, Result};
use k256::{
    ecdsa::VerifyingKey,
    elliptic_curve::{
        point::DecompressPoint, scalar::ScalarPrimitive, sec1::ToEncodedPoint,
    },
    AffinePoint, EncodedPoint, FieldBytes, Scalar, Secp256k1,
};

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::{fmt, str::FromStr};
use subtle::Choice;

/// Ethereum public address that may be converted to and from
/// a string.
///
/// It must begin with 0x and be followed with 20 bytes hex-encoded.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, Hash, Eq, PartialEq)]
#[serde(try_from = "String", into = "String")]
pub struct Address([u8; 20]);

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl Default for Address {
    fn default() -> Self {
        Self([0u8; 20])
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 20]> for Address {
    fn from(value: [u8; 20]) -> Self {
        Self(value)
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if !s.starts_with("0x") {
            return Err(Error::BadAddressPrefix);
        }
        let bytes = hex::decode(&s[2..])?;
        let buffer: [u8; 20] = bytes.as_slice().try_into()?;
        Ok(Address(buffer))
    }
}

impl From<Address> for String {
    fn from(value: Address) -> String {
        value.to_string()
    }
}

impl From<Address> for [u8; 20] {
    fn from(value: Address) -> [u8; 20] {
        value.0
    }
}

impl TryFrom<String> for Address {
    type Error = Error;
    fn try_from(value: String) -> Result<Self> {
        <Address as FromStr>::from_str(&value)
    }
}

impl<'a> From<&'a [u8; 64]> for Address {
    fn from(bytes: &'a [u8; 64]) -> Self {
        let digest = Keccak256::digest(bytes);
        let final_bytes = &digest[12..];
        Self(final_bytes.try_into().unwrap())
    }
}

impl From<[u8; 64]> for Address {
    fn from(bytes: [u8; 64]) -> Self {
        (&bytes).into()
    }
}

impl<'a> TryFrom<&'a VerifyingKey> for Address {
    type Error = Error;

    fn try_from(key: &'a VerifyingKey) -> Result<Self> {
        let point = key.to_encoded_point(true);
        let bytes: [u8; 33] = point.as_bytes().try_into()?;
        (&bytes).try_into()
        //let bytes: [u8; 33] = key.
        //to_encoded_point(true).as_bytes().try_into()?;
        //bytes.into()
    }
}

impl TryFrom<VerifyingKey> for Address {
    type Error = Error;
    fn try_from(key: VerifyingKey) -> Result<Self> {
        (&key).try_into()
    }
}

impl<'a> TryFrom<&'a [u8; 33]> for Address {
    type Error = Error;
    fn try_from(
        bytes: &'a [u8; 33],
    ) -> std::result::Result<Self, Self::Error> {
        let point = decompress(bytes)?;
        let x: [u8; 32] = *point.x().unwrap().as_ref();
        let y: [u8; 32] = *point.y().unwrap().as_ref();
        let bytes: [u8; 64] = [x, y].concat().as_slice().try_into()?;
        Ok((&bytes).into())
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
    let scalar_core = ScalarPrimitive::<Secp256k1>::from_slice(x)?;
    let scalar = Scalar::from(scalar_core);
    let x_bytes = FieldBytes::from(scalar);
    let point = AffinePoint::decompress(&x_bytes, y_is_odd).unwrap();
    let point = point.to_encoded_point(false);
    Ok(point)
}
