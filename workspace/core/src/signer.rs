//! Traits and types for signing messages.
use async_trait::async_trait;
use binary_stream::{
    BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};
use web3_address::ethereum::Address;
use web3_signature::Signature;

use crate::Result;

/// Signature that can be encoded and decoded to binary.
#[derive(Default)]
pub struct BinarySignature(Signature);

impl Encode for BinarySignature {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        // 65 byte signature
        let buffer = self.0.to_bytes();
        writer.write_bytes(buffer)?;
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
    fn address(&self) -> Result<Address>;

    /// Clone a boxed version of this signer.
    fn clone_boxed(&self) -> BoxedSigner;

    /// Get the bytes for this signing key.
    fn to_bytes(&self) -> Vec<u8>;
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

/// ECDSA signer using the Secp256k1 curve from the k256 library.
pub mod ecdsa {
    use async_trait::async_trait;
    use k256::ecdsa::{hazmat::SignPrimitive, SigningKey};
    use sha2::Sha256;
    use sha3::{Digest, Keccak256};
    use web3_address::ethereum::Address;
    use web3_signature::Signature;

    use super::{BoxedSigner, SignSync, Signer};
    use crate::Result;

    /// Signer for a single party key.
    #[derive(Clone)]
    pub struct SingleParty(pub SigningKey);

    impl SingleParty {
        /// Generate a new random single party signing key.
        pub fn new_random() -> SingleParty {
            let signing_key = SigningKey::random(&mut rand::thread_rng());
            SingleParty(signing_key)
        }
    }

    #[async_trait]
    impl Signer for SingleParty {
        fn clone_boxed(&self) -> BoxedSigner {
            Box::new(self.clone())
        }

        fn to_bytes(&self) -> Vec<u8> {
            self.0.to_bytes().as_slice().to_vec()
        }

        async fn sign(&self, message: &[u8]) -> Result<Signature> {
            self.sign_sync(message)
        }

        fn address(&self) -> Result<Address> {
            let point = self.0.verifying_key().to_encoded_point(true);
            let bytes: [u8; 33] = point.as_bytes().try_into()?;
            let address: Address = (&bytes).try_into()?;
            Ok(address)
        }
    }

    impl SignSync for SingleParty {
        fn sign_sync(&self, message: &[u8]) -> Result<Signature> {
            let digest = Keccak256::digest(message);
            let result = self
                .0
                .as_nonzero_scalar()
                .try_sign_prehashed_rfc6979::<Sha256>(digest, b"")?;
            let sig: Signature = result.try_into()?;
            Ok(sig)
        }
    }

    impl TryFrom<[u8; 32]> for SingleParty {
        type Error = crate::Error;
        fn try_from(
            value: [u8; 32],
        ) -> std::result::Result<Self, Self::Error> {
            (&value).try_into()
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

    // TODO(muji) Integation with multi-party-ecdsa / cggmp-threshold-ecdsa
}
