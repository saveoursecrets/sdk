//! Authentication helper functions for extracting an address
//! from a signature given in bearer authorization data.
use axum::headers::{authorization::Bearer, Authorization};
use serde::Deserialize;

use sos_sdk::{
    decode,
    signer::ecdsa::{recover_address, BinaryEcdsaSignature, Address, Signature},
};
//use web3_signature::Signature;

use super::{Error, Result};

/// An RPC message and authorization encoded in a query string.
#[derive(Debug, Deserialize)]
pub struct QueryMessage {
    pub bearer: String,
    pub public_key: String,
}

#[derive(Debug)]
pub struct BearerToken {
    pub address: Address,
}

impl BearerToken {
    /// Create a new bearer token.
    pub async fn new(token: &str, message: &[u8]) -> Result<Self> {
        
        // When a token contains a period we are expecting 
        // an account signature and a device signature
        let token = if token.contains('.') {
            token.split_once('.')
                .map(|s| (s.0, Some(s.1)))
        } else {
            Some((token, None))
        };

        let token = token.ok_or_else(|| Error::BadRequest)?;
        let (account_token, device_token) = token;

        let value = bs58::decode(account_token).into_vec()?;
        let binary_sig: BinaryEcdsaSignature = decode(&value).await?;
        let signature: Signature = binary_sig.into();
        let address = recover_address(signature, message)?;

        Ok(Self {
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
