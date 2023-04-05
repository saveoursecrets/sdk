//! Traits and types for signing messages.
use async_trait::async_trait;
use binary_stream::{
    BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};
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

/// Boxed signer.
type BoxedSigner<O, A> =
    Box<dyn Signer<Output = O, Address = A> + Sync + Send + 'static>;

/// Trait for implementations that can sign a message.
#[async_trait]
pub trait Signer {
    /// The signature output when signing.
    type Output;

    /// The type that represents an address for the signer.
    type Address;

    /// Sign a message and generate a recoverable signature.
    ///
    /// The message digest used will be keccak256.
    ///
    /// Note that libsecp256k1 uses SHA256 for it's digest
    /// so these signatures are not compatible with libsecp256k1.
    async fn sign(&self, message: &[u8]) -> Result<Self::Output>;

    /// Compute the public address for this signer.
    fn address(&self) -> Result<Self::Address>;

    /// Clone a boxed version of this signer.
    fn clone_boxed(&self) -> BoxedSigner<Self::Output, Self::Address>;

    /// Get the bytes for this signing key.
    fn to_bytes(&self) -> Vec<u8>;
}

/// ECDSA signer using the Secp256k1 curve from the k256 library.
pub mod ecdsa {
    use async_trait::async_trait;
    use k256::ecdsa::{hazmat::SignPrimitive, SigningKey};
    use rand::rngs::OsRng;
    use sha2::Sha256;
    use sha3::{Digest, Keccak256};
    use web3_address::ethereum::Address;
    use web3_signature::Signature;

    use super::{BoxedSigner, Signer};
    use crate::Result;

    /// Signer for single party ECDSA signatures.
    pub type BoxedEcdsaSigner = BoxedSigner<Signature, Address>;

    impl Clone for BoxedEcdsaSigner {
        fn clone(&self) -> Self {
            self.clone_boxed()
        }
    }

    /// Signer for a single party key.
    #[derive(Clone)]
    pub struct SingleParty(pub SigningKey);

    impl SingleParty {
        /// Generate a new random single party signing key.
        pub fn new_random() -> SingleParty {
            let mut csprng = OsRng {};
            let signing_key = SigningKey::random(&mut csprng);
            SingleParty(signing_key)
        }
    }

    #[async_trait]
    impl Signer for SingleParty {
        type Output = Signature;
        type Address = Address;

        fn clone_boxed(&self) -> BoxedEcdsaSigner {
            Box::new(self.clone())
        }

        fn to_bytes(&self) -> Vec<u8> {
            self.0.to_bytes().as_slice().to_vec()
        }

        async fn sign(&self, message: &[u8]) -> Result<Self::Output> {
            let digest = Keccak256::digest(message);
            let result = self
                .0
                .as_nonzero_scalar()
                .try_sign_prehashed_rfc6979::<Sha256>(digest, b"")?;
            let sig: Signature = result.try_into()?;
            Ok(sig)
        }

        fn address(&self) -> Result<Self::Address> {
            let point = self.0.verifying_key().to_encoded_point(true);
            let bytes: [u8; 33] = point.as_bytes().try_into()?;
            let address: Address = (&bytes).try_into()?;
            Ok(address)
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

/// ED25519 signer using the ed25519-dalek library.
pub mod ed25519 {
    use async_trait::async_trait;
    use ed25519_dalek::{
        Signature, Signer as Ed25519Signer, SigningKey, SECRET_KEY_LENGTH,
    };
    use rand::rngs::OsRng;

    use super::{BoxedSigner, Signer};
    use crate::Result;

    /// Signer for single party Ed25519signatures.
    pub type BoxedEd25519Signer = BoxedSigner<Signature, String>;

    impl Clone for BoxedEd25519Signer {
        fn clone(&self) -> Self {
            self.clone_boxed()
        }
    }

    /// Signer for a single party key.
    pub struct SingleParty(pub SigningKey);

    /// Clone this signer.
    impl Clone for SingleParty {
        fn clone(&self) -> Self {
            Self(SigningKey::from_bytes(&self.0.to_bytes()))
        }
    }

    impl SingleParty {
        /// Generate a new random single party signing key.
        pub fn new_random() -> SingleParty {
            let mut csprng = OsRng {};
            let signing_key = SigningKey::generate(&mut csprng);
            SingleParty(signing_key)
        }
    }

    #[async_trait]
    impl Signer for SingleParty {
        type Output = Signature;
        type Address = String;

        fn clone_boxed(&self) -> BoxedEd25519Signer {
            Box::new(self.clone())
        }

        fn to_bytes(&self) -> Vec<u8> {
            self.0.to_bytes().as_slice().to_vec()
        }

        async fn sign(&self, message: &[u8]) -> Result<Self::Output> {
            Ok(self.0.sign(message))
        }

        fn address(&self) -> Result<Self::Address> {
            let mut encoded = String::new();
            let verifying_key = self.0.verifying_key();
            bs58::encode(verifying_key.as_bytes()).into(&mut encoded)?;
            Ok(encoded)
        }
    }

    impl TryFrom<[u8; SECRET_KEY_LENGTH]> for SingleParty {
        type Error = crate::Error;
        fn try_from(
            value: [u8; SECRET_KEY_LENGTH],
        ) -> std::result::Result<Self, Self::Error> {
            (&value).try_into()
        }
    }

    impl<'a> TryFrom<&'a [u8; SECRET_KEY_LENGTH]> for SingleParty {
        type Error = crate::Error;
        fn try_from(
            value: &'a [u8; SECRET_KEY_LENGTH],
        ) -> std::result::Result<Self, Self::Error> {
            Ok(Self(SigningKey::from_bytes(value)))
        }
    }
}
