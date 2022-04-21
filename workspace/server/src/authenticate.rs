//! Authentication helper functions and types for the authentication challenge and response.
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::SystemTime,
};
use uuid::Uuid;

use axum::{
    body::Bytes,
    headers::{authorization::Bearer, Authorization},
    http::StatusCode,
};

use sos_core::{
    address::AddressStr, decode, encode, k256::ecdsa::recoverable,
    vault::Vault, web3_signature::Signature,
};

use crate::{Error, Result};

type Challenge = [u8; 32];

#[derive(Debug)]
pub struct BearerToken {
    //public_key: [u8; 33],
    pub address: AddressStr,
}

/// Extract a public key and address from the ECDSA signature
/// in the authorization header.
///
/// Decodes the token from base64 and then parses as a JSON representation
/// of a Signature with r, s and v values.
///
/// The signature is then converted to a recoverable signature and the public
/// key is extracted using the body bytes as the message that has been signed.
pub fn bearer(
    authorization: Authorization<Bearer>,
    body: &Bytes,
) -> Result<(StatusCode, Option<BearerToken>)> {
    let result = if let Ok(value) = base64::decode(authorization.token()) {
        if let Ok(signature) = serde_json::from_slice::<Signature>(&value) {
            let recoverable: recoverable::Signature = signature.try_into()?;
            let public_key = recoverable.recover_verify_key(body)?;
            let public_key: [u8; 33] =
                public_key.to_bytes().as_slice().try_into()?;
            let address: AddressStr = (&public_key).try_into()?;
            (
                StatusCode::OK,
                Some(BearerToken {
                    //public_key,
                    address,
                }),
            )
        } else {
            (StatusCode::BAD_REQUEST, None)
        }
    } else {
        (StatusCode::BAD_REQUEST, None)
    };

    Ok(result)
}

/// Encapsulates a collection of authentication challenges.
#[derive(Debug)]
pub struct Authentication {
    challenges: Arc<RwLock<HashMap<Uuid, (Challenge, SystemTime)>>>,
}

impl Default for Authentication {
    fn default() -> Self {
        Self {
            challenges: Arc::new(RwLock::new(Default::default())),
        }
    }
}

impl Authentication {
    /// Create a new challenge.
    ///
    /// A challenge is a v4 UUID that identifies the challenge
    /// and a message that must be signed to authenticate.
    ///
    /// The message is a keccak256 digest of the UUID.
    pub fn new_challenge(&mut self) -> (Uuid, Challenge) {
        let now = SystemTime::now();
        let id = Uuid::new_v4();
        let challenge: [u8; 32] =
            Keccak256::digest(id.as_bytes()).try_into().unwrap();
        let mut writer = self.challenges.write().unwrap();
        writer.entry(id).or_insert((challenge, now));
        (id, challenge)
    }

    /// Remove and return a challenge.
    pub fn remove(&mut self, uuid: &Uuid) -> Option<(Challenge, SystemTime)> {
        let mut writer = self.challenges.write().unwrap();
        writer.remove(uuid)
    }
}
