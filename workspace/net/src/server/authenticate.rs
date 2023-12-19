//! Authentication helper functions for extracting an address
//! from a signature given in bearer authorization data.
use axum::headers::{authorization::Bearer, Authorization};
use serde::Deserialize;

use sos_sdk::{
    decode,
    signer::ecdsa::{recover_address, BinaryEcdsaSignature},
};
use web3_address::ethereum::Address;
use web3_signature::Signature;

use super::Result;

/// An RPC message and authorization encoded in a query string.
#[derive(Debug, Deserialize)]
pub struct QueryMessage {
    //pub request: String,
    pub bearer: String,
    pub public_key: String,
}

#[derive(Debug)]
pub struct BearerToken {
    //public_key: [u8; 33],
    pub address: Address,
}

impl BearerToken {
    /// Create a new bearer token.
    pub async fn new(token: &str, message: &[u8]) -> Result<Self> {
        let value = bs58::decode(token).into_vec()?;
        let binary_sig: BinaryEcdsaSignature = decode(&value).await?;
        let signature: Signature = binary_sig.into();
        let address = recover_address(signature, message)?;
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
pub async fn bearer<B>(
    authorization: Authorization<Bearer>,
    body: B,
) -> Result<BearerToken>
where
    B: AsRef<[u8]>,
{
    BearerToken::new(authorization.token(), body.as_ref()).await
}
