//! Traits and types for signing messages.
use k256::{
    ecdsa::{SigningKey, recoverable::Signature, signature::Signer as EcdsaSigner},
};
use async_trait::async_trait;

use crate::Result;

/// Trait for implementations that can sign a message.
#[async_trait]
pub trait Signer {
    /// Sign a message and generate a recoverable signature.
    ///
    /// The message digest used will be keccak256.
    ///
    /// Note that libsecp256k1 uses SHA256 for it's digest 
    /// so these signatures are not compatible with libsecp256k1.
    async fn sign(&self, message: &[u8]) -> Result<Signature>;
}

/// Signer for a single party key.
pub struct SingleParty(SigningKey);

#[async_trait]
impl Signer for SingleParty {
    async fn sign(&self, message: &[u8]) -> Result<Signature> {
        Ok(self.0.sign(message))
    }
}

// TODO(muji) Integation with multi-party-ecdsa
