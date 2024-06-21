//! Authentication helper functions for extracting an address
//! from a signature given in bearer authorization data.
use axum_extra::headers::{authorization::Bearer, Authorization};

use sos_protocol::sdk::{
    decode,
    signer::{
        ecdsa::{self, recover_address, Address, BinaryEcdsaSignature},
        ed25519::{self, BinaryEd25519Signature},
    },
};

use super::{Error, Result};

#[derive(Debug)]
pub struct BearerToken {
    pub address: Address,
    pub device_signature: Option<ed25519::Signature>,
}

impl BearerToken {
    /// Create a new bearer token.
    pub async fn new(token: &str, message: &[u8]) -> Result<Self> {
        // When a token contains a period we are expecting
        // an account signature and a device signature
        let token = if token.contains('.') {
            token.split_once('.').map(|s| (s.0, Some(s.1)))
        } else {
            Some((token, None))
        };

        let token = token.ok_or_else(|| Error::BadRequest)?;
        let (account_token, device_token) = token;

        let value = bs58::decode(account_token).into_vec()?;
        let buffer: BinaryEcdsaSignature = decode(&value).await?;
        let signature: ecdsa::Signature = buffer.into();
        let address = recover_address(signature, message)?;

        let device_signature = if let Some(device_token) = device_token {
            let value = bs58::decode(device_token).into_vec()?;
            let buffer: BinaryEd25519Signature = decode(&value).await?;
            let signature: ed25519::Signature = buffer.into();
            Some(signature)
        } else {
            None
        };

        Ok(Self {
            address,
            device_signature,
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
