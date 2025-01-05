//! Private identity manages the identity vault,
//! account signing key, device signing key and delegated
//! passwords.
use sos_core::AccountId;
use sos_signer::ecdsa::{Address, BoxedEcdsaSigner};

/// Private identity containing the in-memory identity vault
/// and signing keys.
pub struct PrivateIdentity {
    /// Address of the signing key.
    pub(super) address: Address,
    /// Private signing key for the identity.
    pub(super) signer: BoxedEcdsaSigner,

    /// AGE identity keypair.
    #[allow(dead_code)]
    pub(super) shared_private: age::x25519::Identity,
    /// AGE recipient public key.
    pub(super) shared_public: age::x25519::Recipient,
}

impl PrivateIdentity {
    /// Address of the signing key.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Signing key for this user.
    pub fn signer(&self) -> &BoxedEcdsaSigner {
        &self.signer
    }

    /// Recipient public key for sharing.
    pub fn recipient(&self) -> &age::x25519::Recipient {
        &self.shared_public
    }
}
