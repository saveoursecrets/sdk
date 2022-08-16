//! Authentication helper functions for extracting an address
//! from a signature given in bearer authorization data.
use axum::headers::{authorization::Bearer, Authorization};
use serde::Deserialize;

use sos_core::{address::AddressStr, decode, signer::BinarySignature};

use k256::ecdsa::recoverable;
use web3_signature::Signature;
use uuid::Uuid;

use super::Result;

#[derive(Debug, Deserialize)]
pub struct SignedQuery {
    #[serde(deserialize_with = "hex::serde::deserialize")]
    message: Vec<u8>,
    token: String,
}

impl SignedQuery {
    pub fn bearer(&self) -> Result<BearerToken> {
        BearerToken::new(&self.token, &self.message)
    }
}

/// An RPC message in a query string encoded as base58.
#[derive(Debug, Deserialize)]
pub struct QueryMessage {
    pub session: Uuid,
    pub request: String,
    pub bearer: String,
}

#[derive(Debug)]
pub struct BearerToken {
    //public_key: [u8; 33],
    pub address: AddressStr,
}

impl BearerToken {
    /// Create a new bearer token.
    pub fn new(token: &str, message: &[u8]) -> Result<Self> {
        let value = bs58::decode(token).into_vec()?;
        let binary_sig: BinarySignature = decode(&value)?;
        let signature: Signature = binary_sig.into();
        let recoverable: recoverable::Signature = signature.try_into()?;
        let public_key = recoverable.recover_verifying_key(message)?;
        let public_key: [u8; 33] =
            public_key.to_bytes().as_slice().try_into()?;
        let address: AddressStr = (&public_key).try_into()?;

        Ok(Self {
            //public_key,
            address,
        })
    }
}

/// Extract a public key and address from the ECDSA signature
/// in the authorization header.
///
/// Decodes the token from base58 and then parses a 65-bytes binary
/// representation of a signature with r, s and v values.
///
/// The signature is then converted to a recoverable signature and the public
/// key is extracted using the body bytes as the message that has been signed.
pub fn bearer<B>(
    authorization: Authorization<Bearer>,
    body: B,
) -> Result<BearerToken>
where
    B: AsRef<[u8]>,
{
    BearerToken::new(authorization.token(), body.as_ref())
}
