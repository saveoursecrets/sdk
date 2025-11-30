//! Traits and types for signing messages.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod encoding;
mod error;

pub use error::Error;

/// Result type for the signer library.
pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Boxed signer.
type BoxedSigner<O, V> =
    Box<dyn Signer<Output = O, Verifying = V> + Sync + Send + 'static>;

/// Trait for implementations that can sign a message.
///
/// This trait is declared with an async signature so that
/// in the future we can support threshold signatures
/// which are inherently asynchronous.
#[async_trait::async_trait]
pub trait Signer {
    /// Signature output.
    type Output;

    /// Verifying key.
    type Verifying;

    /// Sign a message and generate a recoverable signature.
    ///
    /// The message digest used will be keccak256.
    ///
    /// Note that libsecp256k1 uses SHA256 for it's digest
    /// so these signatures are not compatible with libsecp256k1.
    async fn sign(&self, message: &[u8]) -> Result<Self::Output>;

    /// Sign a message synchronously.
    fn sign_sync(&self, message: &[u8]) -> Result<Self::Output>;

    /// Get the verifying key for this signer.
    fn verifying_key(&self) -> Self::Verifying;

    /// Clone a boxed version of this signer.
    fn clone_boxed(&self) -> BoxedSigner<Self::Output, Self::Verifying>;

    /// Get the bytes for this signing key.
    fn to_bytes(&self) -> Vec<u8>;
}

/// ECDSA signer using the Secp256k1 curve from the k256 library.
pub mod ecdsa {
    use async_trait::async_trait;
    use rand::rngs::OsRng;
    use sha2::Sha256;
    use sha3::{Digest, Keccak256};

    pub use k256::ecdsa::{
        hazmat::SignPrimitive, RecoveryId, Signature, SigningKey,
        VerifyingKey,
    };

    use super::{BoxedSigner, Signer};
    use crate::Result;

    /// Signer for single party ECDSA signatures.
    pub type BoxedEcdsaSigner =
        BoxedSigner<(Signature, Option<RecoveryId>), VerifyingKey>;

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
        type Output = (Signature, Option<RecoveryId>);
        type Verifying = VerifyingKey;

        fn clone_boxed(&self) -> BoxedEcdsaSigner {
            Box::new(self.clone())
        }

        fn to_bytes(&self) -> Vec<u8> {
            self.0.to_bytes().as_slice().to_vec()
        }

        fn verifying_key(&self) -> Self::Verifying {
            *self.0.verifying_key()
        }

        async fn sign(&self, message: &[u8]) -> Result<Self::Output> {
            self.sign_sync(message)
        }

        fn sign_sync(&self, message: &[u8]) -> Result<Self::Output> {
            let digest = Keccak256::digest(message);
            let result = self
                .0
                .as_nonzero_scalar()
                .try_sign_prehashed_rfc6979::<Sha256>(
                    digest.as_slice().into(),
                    b"",
                )?;
            Ok(result)
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
            Ok(Self(SigningKey::from_bytes(value.into())?))
        }
    }
}

/// ED25519 signer using the ed25519-dalek library.
pub mod ed25519 {
    use async_trait::async_trait;
    pub use ed25519_dalek::{
        Signature, Signer as Ed25519Signer, SigningKey, Verifier,
        VerifyingKey, SECRET_KEY_LENGTH,
    };
    use rand::rngs::OsRng;

    use super::{BoxedSigner, Signer};
    use crate::Result;

    /// Signer for single party Ed25519signatures.
    pub type BoxedEd25519Signer = BoxedSigner<Signature, VerifyingKey>;

    impl Clone for BoxedEd25519Signer {
        fn clone(&self) -> Self {
            self.clone_boxed()
        }
    }

    /// Signature that can be encoded and decoded to binary.
    pub struct BinaryEd25519Signature(pub(crate) Signature);

    impl Default for BinaryEd25519Signature {
        fn default() -> Self {
            Self(Signature::from_bytes(&[0; 64]))
        }
    }

    impl From<Signature> for BinaryEd25519Signature {
        fn from(value: Signature) -> Self {
            BinaryEd25519Signature(value)
        }
    }

    impl From<BinaryEd25519Signature> for Signature {
        fn from(value: BinaryEd25519Signature) -> Self {
            value.0
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
        type Verifying = VerifyingKey;

        fn clone_boxed(&self) -> BoxedEd25519Signer {
            Box::new(self.clone())
        }

        fn to_bytes(&self) -> Vec<u8> {
            self.0.to_bytes().as_slice().to_vec()
        }

        fn verifying_key(&self) -> Self::Verifying {
            self.0.verifying_key()
        }

        async fn sign(&self, message: &[u8]) -> Result<Self::Output> {
            self.sign_sync(message)
        }

        fn sign_sync(&self, message: &[u8]) -> Result<Self::Output> {
            Ok(self.0.sign(message))
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

    impl TryFrom<&[u8]> for SingleParty {
        type Error = crate::Error;
        fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
            let value: [u8; SECRET_KEY_LENGTH] = value.try_into()?;
            value.try_into()
        }
    }
}
