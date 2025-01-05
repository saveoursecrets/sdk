//! Authentication helper functions for extracting an address
//! from a signature given in bearer authorization data.
use super::{Error, Result};
use axum_extra::headers::{authorization::Bearer, Authorization};
use sos_core::{decode, AccountId};
use sos_signer::{
    ecdsa::{self, recover_address, BinaryEcdsaSignature},
    ed25519::{self, BinaryEd25519Signature},
};

#[derive(Debug)]
pub struct BearerToken {
    pub account_id: AccountId,
    pub device_signature: ed25519::Signature,
}

impl BearerToken {
    /// Create a new bearer token.
    pub async fn new(
        header_account_id: Option<AccountId>,
        token: &str,
        message: &[u8],
    ) -> Result<Self> {
        let has_period_delimiter = token.contains('.');

        #[allow(unused_assignments)]
        let mut account_id: Option<AccountId> = None;
        #[allow(unused_assignments)]
        let mut device_signature: Option<ed25519::Signature> = None;

        match (header_account_id, has_period_delimiter) {
            // Version 2 of the bearer format does not include
            // an account signature but extracts the AccountId
            // from a header instead
            (Some(id), false) => {
                account_id = Some(id);

                let value = bs58::decode(token).into_vec()?;
                let buffer: BinaryEd25519Signature = decode(&value).await?;
                let signature: ed25519::Signature = buffer.into();
                device_signature = Some(signature);
            }
            // Concatenated account signature and device signature with
            // account identifier in the header is deprecated but we will
            // support it for now, preferring the value in the header
            (Some(id), true) => {
                account_id = Some(id);

                let (_, device_token) = token.split_once('.').unwrap();
                let value = bs58::decode(device_token).into_vec()?;
                let buffer: BinaryEd25519Signature = decode(&value).await?;
                let signature: ed25519::Signature = buffer.into();
                device_signature = Some(signature);
            }
            // Legacy version 1 encoding extracts the account identifier
            // from the ECDSA signature public key
            (None, true) => {
                let (account_token, device_token) =
                    token.split_once('.').unwrap();

                let value = bs58::decode(account_token).into_vec()?;
                let buffer: BinaryEcdsaSignature = decode(&value).await?;
                let signature: ecdsa::Signature = buffer.into();
                account_id =
                    Some(recover_address(signature, message)?.into());

                let value = bs58::decode(device_token).into_vec()?;
                let buffer: BinaryEd25519Signature = decode(&value).await?;
                let signature: ed25519::Signature = buffer.into();
                device_signature = Some(signature);
            }
            // Legacy without a device signature is now forbidden.
            //
            // This was previously accepted in v0.15.x.
            (None, false) => {
                return Err(Error::Forbidden);
            }
        }

        let account_id = account_id.ok_or_else(|| Error::BadRequest)?;
        let device_signature =
            device_signature.ok_or_else(|| Error::BadRequest)?;

        Ok(Self {
            account_id,
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
    account_id: Option<AccountId>,
    authorization: Authorization<Bearer>,
    body: B,
) -> Result<BearerToken>
where
    B: AsRef<[u8]>,
{
    BearerToken::new(account_id, authorization.token(), body.as_ref()).await
}
