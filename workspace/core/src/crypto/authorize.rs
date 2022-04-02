//! Authorization routines using ECDSA.
use serde_binary::{
    Encode, Decode, Serializer, Deserializer,
    binary_rw::{BinaryReader, BinaryWriter}
};
use k256::ecdsa::{
    signature::Signature as EcdsaSignature, signature::Verifier, Signature, SigningKey,
    VerifyingKey,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

use super::{keypair::KeyPart, types::*};
use crate::{
    address::{address_compressed, address_decompressed},
    Error, Result,
};

/// Size of a compressed public key.
pub const COMPRESSED: u8 = 33;

/// Size of a decompressed public key.
pub const DECOMPRESSED: u8 = 65;

/// Private key used by clients to authorize access to a vault.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct PrivateKey {
    type_id: u8,
    key: Vec<u8>,
}

impl From<KeyPart> for PrivateKey {
    fn from(value: KeyPart) -> Self {
        let KeyPart { type_id, key } = value;
        Self { type_id, key }
    }
}

impl TryFrom<&PrivateKey> for SigningKey {
    type Error = Error;
    fn try_from(value: &PrivateKey) -> std::result::Result<Self, Self::Error> {
        match value.type_id {
            K256 => Ok(SigningKey::from_bytes(&value.key)?),
            _ => Err(Error::UnknownKeyTypeId),
        }
    }
}

/// An ECDSA public key abstraction designed to allow either
/// single party or multi-party access using different ECDSA
/// implementations.
#[derive(Serialize, Deserialize, Debug, Default, Eq, PartialEq)]
pub struct PublicKey {
    /// Whether the key data is compressed, so that we know
    /// how many bytes to decode.
    compressed: bool,
    /// The public key bytes.
    key_data: KeyData,
}

/// Represents the public key data bytes.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub enum KeyData {
    /// Compressed public key of 0x02 or 0x03 followed by 32 bytes for the x coordinate
    Compressed([u8; COMPRESSED as usize]),
    /// Decompressed public key of 0x04 followed by 64 bytes for both x and y coordinates
    Decompressed([u8; DECOMPRESSED as usize]),
}

impl Default for KeyData {
    fn default() -> Self {
        Self::Compressed([0; 33])
    }
}

impl KeyData {
    fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::Compressed(bytes) => bytes.to_vec(),
            Self::Decompressed(bytes) => bytes.to_vec(),
        }
    }
}

impl PublicKey {
    /// Compute the address for this public key.
    pub fn address(&self) -> Result<String> {
        match self.key_data {
            KeyData::Compressed(ref bytes) => address_compressed(bytes),
            KeyData::Decompressed(ref bytes) => address_decompressed(bytes),
        }
    }
}

impl TryFrom<KeyPart> for PublicKey {
    type Error = Error;
    fn try_from(value: KeyPart) -> std::result::Result<Self, Self::Error> {
        match value.type_id {
            K256 => {
                if value.key.len() != COMPRESSED as usize {
                    return Err(Error::InvalidPublicKeyLength(COMPRESSED, value.key.len()));
                }

                if value.key[0] != 0x02 && value.key[0] != 0x03 {
                    return Err(Error::BadPublicKeyByte);
                }

                let bytes: [u8; COMPRESSED as usize] = value.key.as_slice().try_into()?;
                Ok(PublicKey {
                    compressed: true,
                    key_data: KeyData::Compressed(bytes),
                })
            }
            _ => Err(Error::UnknownKeyTypeId),
        }
    }
}

impl From<VerifyingKey> for PublicKey {
    fn from(key: VerifyingKey) -> Self {
        let key_data: [u8; COMPRESSED as usize] = key.to_bytes().as_slice().try_into().unwrap();
        Self {
            compressed: true,
            key_data: KeyData::Compressed(key_data),
        }
    }
}

impl TryFrom<&PublicKey> for VerifyingKey {
    type Error = Error;
    fn try_from(value: &PublicKey) -> std::result::Result<Self, Self::Error> {
        match value.key_data {
            KeyData::Compressed(ref bytes) => Ok(VerifyingKey::from_sec1_bytes(bytes)?),
            _ => Err(Error::NotCompressedPublicKey),
        }
    }
}

/*
impl Encode for PublicKey {
    fn encode(&self, writer: &mut BinaryWriter) -> Result<()> {
        writer.write_bool(self.compressed)?;
        writer.write_bytes(self.key_data.to_vec())?;
        Ok(())
    }
}

impl Decode for PublicKey {
    fn decode(&mut self, reader: &mut BinaryReader) -> Result<()> {
        self.compressed = reader.read_bool()?;
        self.key_data = if self.compressed {
            let bytes: [u8; COMPRESSED as usize] = reader
                .read_bytes(COMPRESSED as usize)?
                .as_slice()
                .try_into()?;
            KeyData::Compressed(bytes)
        } else {
            let bytes: [u8; DECOMPRESSED as usize] = reader
                .read_bytes(DECOMPRESSED as usize)?
                .as_slice()
                .try_into()?;
            KeyData::Decompressed(bytes)
        };
        Ok(())
    }
}
*/

/// Challenge sent to clients that wish to authorize.
///
/// The `id` is a unique identifier for the authorization request
/// and the `message` must be signed by the client using their ECDSA
/// signing (private) key.
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Challenge {
    #[serde(
        serialize_with = "hex::serde::serialize",
        deserialize_with = "hex::serde::deserialize"
    )]
    id: [u8; 32],
    #[serde(
        serialize_with = "hex::serde::serialize",
        deserialize_with = "hex::serde::deserialize"
    )]
    message: [u8; 32],
    /// Vault name for this challenge.
    #[serde(skip)]
    vault_name: String,
}

impl Challenge {
    /// Generate a new authorization challenge.
    pub fn new(vault_name: String) -> Self {
        Self {
            id: rand::thread_rng().gen(),
            message: rand::thread_rng().gen(),
            vault_name,
        }
    }

    /// Get the identifier for the challenge.
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// Get the message to sign.
    pub fn message(&self) -> &[u8; 32] {
        &self.message
    }
}

/// Authorization response from a client to a challenge,
///
/// The `id` must exactly match the `Challenge`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ChallengeResponse {
    #[serde(
        serialize_with = "hex::serde::serialize",
        deserialize_with = "hex::serde::deserialize"
    )]
    id: [u8; 32],
    #[serde(
        serialize_with = "hex::serde::serialize",
        deserialize_with = "hex::serde::deserialize"
    )]
    signature: Vec<u8>,
}

impl ChallengeResponse {
    /// Create a challenge response.
    pub fn new(id: [u8; 32], signature: Vec<u8>) -> Self {
        Self { id, signature }
    }

    /// Get the identifier for the challenge response.
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// Get the response signature.
    pub fn signature(&self) -> &Vec<u8> {
        &self.signature
    }
}

/// Encapsulates a collection of authorization challenges.
#[derive(Debug)]
pub struct Authorization {
    challenges: Arc<RwLock<Vec<Challenge>>>,
}

impl Default for Authorization {
    fn default() -> Self {
        Self {
            challenges: Arc::new(RwLock::new(Default::default())),
        }
    }
}

impl Authorization {
    /// Add a challenge.
    pub fn add(&mut self, challenge: Challenge) {
        let mut writer = self.challenges.write().unwrap();
        writer.push(challenge);
    }

    /// Get the name of a vault from a challenge response by searching for
    /// the source challenge.
    pub fn vault_name(&self, response: &ChallengeResponse) -> Option<String> {
        let reader = self.challenges.read().unwrap();
        if let Some(challenge) = reader.iter().find(|c| c.id() == response.id()) {
            Some(challenge.vault_name.clone())
        } else {
            None
        }
    }

    /// Determine if a challenge response is valid.
    ///
    /// Returns `Result::Ok` if the authorization was successful.
    pub fn authorize(
        &self,
        public_keys: &Vec<PublicKey>,
        response: &ChallengeResponse,
    ) -> Result<()> {
        let mut writer = self.challenges.write().unwrap();

        if let Some(index) = writer.iter().position(|c| c.id() == response.id()) {
            let challenge = writer.remove(index);
            for public_key in public_keys {
                if public_key.compressed {
                    let signature = Signature::from_bytes(response.signature().as_ref())?;
                    let verify_key: VerifyingKey = public_key.try_into()?;
                    if verify_key.verify(challenge.message(), &signature).is_ok() {
                        return Ok(());
                    }
                } else {
                    todo!("support uncompressed public keys")
                }
            }
            return Err(Error::InvalidChallengeResponse);
        }
        Err(Error::ChallengeNotFound)
    }
}

/// High-level functions for creating and verifying JSON web tokens
/// using the Ed25519 algorithm.
pub mod jwt {
    use crate::Result;
    use jwt_simple::{
        algorithms::{Ed25519KeyPair, Ed25519PublicKey, EdDSAKeyPairLike, EdDSAPublicKeyLike},
        claims::{Claims, JWTClaims},
        prelude::coarsetime::Duration,
    };
    use serde::{de::DeserializeOwned, Deserialize, Serialize};

    /// Standard token issuer.
    pub const ISSUER: &str = "sos3.app";

    /// Type for the algorithm key pair.
    pub type KeyPair = Ed25519KeyPair;

    /// Type for the issued tokens.
    pub type Token = String;

    /// Standard custom claims.
    #[derive(Serialize, Deserialize)]
    pub struct StandardClaims {
        vault: String,
    }

    /// Generate a new key pair.
    pub fn generate() -> Ed25519KeyPair {
        Ed25519KeyPair::generate()
    }

    /// Create a new token.
    pub fn authorize<C: Serialize + DeserializeOwned>(
        key: &KeyPair,
        claims: JWTClaims<C>,
    ) -> Result<Token> {
        Ok(key.sign(claims)?)
    }

    /// Verify a token.
    pub fn verify<C: Serialize + DeserializeOwned>(
        key: &Ed25519PublicKey,
        token: &str,
    ) -> Result<JWTClaims<C>> {
        Ok(key.verify_token::<C>(token, None)?)
    }

    /// Get the default set of claims for a vault.
    pub fn claims<S: AsRef<str>>(vault: S) -> JWTClaims<StandardClaims> {
        let jwt_claims = StandardClaims {
            vault: vault.as_ref().to_string(),
        };
        let mut claims = Claims::with_custom_claims(jwt_claims, Duration::from_mins(15));
        claims.issuer = Some(ISSUER.to_string());
        claims
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use anyhow::Result;

        #[test]
        fn jwt_sign() -> Result<()> {
            let vault = "mock".to_string();
            let key_pair = generate();
            let public_key = key_pair.public_key();
            let claims = claims(&vault);
            let token = authorize(&key_pair, claims)?;

            //println!("{}", token);

            let claims = verify::<StandardClaims>(&public_key, &token)?;
            assert_eq!(Some(ISSUER.to_string()), claims.issuer);
            assert_eq!(vault, claims.custom.vault);

            //println!("{:#?}", claims);
            Ok(())
        }
    }
}
