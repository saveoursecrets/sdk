//! Private identity manages the identity vault,
//! account signing key, device signing key and delegated
//! passwords.
use sos_core::AccountId;

/// Private identity containing the in-memory identity vault
/// and signing keys.
pub struct PrivateIdentity {
    /// Address of the signing key.
    pub(super) account_id: AccountId,

    /// AGE identity keypair.
    #[allow(dead_code)]
    pub(super) shared_private: age::x25519::Identity,
    /// AGE recipient public key.
    pub(super) shared_public: age::x25519::Recipient,
}

impl PrivateIdentity {
    /// Account identifier.
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Recipient public key for sharing.
    pub fn recipient(&self) -> &age::x25519::Recipient {
        &self.shared_public
    }
}
