//! Traits and types for signing messages.
use async_trait::async_trait;
use binary_stream::{
    BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};
use k256::ecdsa::{
    recoverable, signature::Signer as EcdsaSigner, SigningKey,
};
use web3_signature::Signature;

use crate::{address::AddressStr, Result};

/// Signature that can be encoded and decoded to binary.
#[derive(Default)]
pub struct BinarySignature(Signature);

impl Encode for BinarySignature {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        // 65 byte signature
        let buffer = self.0.to_bytes();
        writer.write_bytes(&buffer)?;
        Ok(())
    }
}

impl Decode for BinarySignature {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        let buffer: [u8; 65] =
            reader.read_bytes(65)?.as_slice().try_into()?;
        self.0 = buffer.into();
        Ok(())
    }
}

impl From<Signature> for BinarySignature {
    fn from(value: Signature) -> Self {
        BinarySignature(value)
    }
}

impl From<BinarySignature> for Signature {
    fn from(value: BinarySignature) -> Self {
        value.0
    }
}

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

    /// Compute the public address for this signer.
    fn address(&self) -> Result<AddressStr>;

    /// Clone a boxed version of this signer.
    fn clone_boxed(&self) -> BoxedSigner;
}

/// Trait for implementations that can sign a message synchronously.
pub trait SignSync {
    /// Sign a message and generate a recoverable signature.
    ///
    /// The message digest used will be keccak256.
    ///
    /// Note that libsecp256k1 uses SHA256 for it's digest
    /// so these signatures are not compatible with libsecp256k1.
    fn sign_sync(&self, message: &[u8]) -> Result<Signature>;
}

/// Boxed signer.
pub type BoxedSigner = Box<dyn Signer + Sync + Send + 'static>;

impl Clone for BoxedSigner {
    fn clone(&self) -> Self {
        self.clone_boxed()
    }
}

/// Signer for a single party key.
#[derive(Clone)]
pub struct SingleParty(pub SigningKey);

#[async_trait]
impl Signer for SingleParty {
    fn clone_boxed(&self) -> BoxedSigner {
        Box::new(self.clone())
    }

    async fn sign(&self, message: &[u8]) -> Result<Signature> {
        let recoverable: recoverable::Signature = self.0.sign(message);
        let sig: Signature = recoverable.into();
        Ok(sig)
    }

    fn address(&self) -> Result<AddressStr> {
        let bytes = self.0.verifying_key().to_bytes();
        let bytes: [u8; 33] = bytes.as_slice().try_into()?;
        let address: AddressStr = (&bytes).try_into()?;
        Ok(address)
    }
}

impl SignSync for SingleParty {
    fn sign_sync(&self, message: &[u8]) -> Result<Signature> {
        let recoverable: recoverable::Signature = self.0.sign(message);
        let sig: Signature = recoverable.into();
        Ok(sig)
    }
}

impl<'a> TryFrom<&'a [u8; 32]> for SingleParty {
    type Error = crate::Error;
    fn try_from(
        value: &'a [u8; 32],
    ) -> std::result::Result<Self, Self::Error> {
        Ok(Self(SigningKey::from_bytes(value)?))
    }
}

// TODO(muji) Integation with multi-party-ecdsa
