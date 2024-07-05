use crate::{
    constants::DEFAULT_VAULT_NAME,
    crypto::{Cipher, KeyDerivation, PrivateKey, Seed},
    encode,
    vault::{Vault, VaultAccess, VaultFlags, VaultId, VaultMeta},
    Result,
};
use age::x25519::{Identity, Recipient};
use secrecy::SecretString;

/// Credentials for a new vault.
pub enum BuilderCredentials<'a> {
    /// Password credentials for the vault.
    Password(SecretString, Option<Seed>),
    /// Shared asymmetric credentials for the vault.
    Shared {
        /// Owner identity of the vault.
        owner: &'a Identity,
        /// Recipients allowed to decrypt vault secrets.
        recipients: Vec<Recipient>,
        /// Whether the vault should be marked as read-only for recipients.
        read_only: bool,
    },
}

/// Builder for a vault.
pub struct VaultBuilder {
    /// Vault identifier.
    id: VaultId,
    /// Public name.
    public_name: String,
    /// Set the private description for the vault.
    description: Option<String>,
    /// Flags for the vault.
    flags: VaultFlags,
    /// Encryption cipher for the vault.
    cipher: Cipher,
    /// Key derivation function.
    kdf: KeyDerivation,
}

impl Default for VaultBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultBuilder {
    /// Create a new vault builder.
    pub fn new() -> Self {
        Self {
            id: VaultId::new_v4(),
            public_name: DEFAULT_VAULT_NAME.to_owned(),
            description: None,
            flags: Default::default(),
            cipher: Default::default(),
            kdf: Default::default(),
            //seed: None,
        }
    }

    /// Set the vault identifier.
    pub fn id(mut self, id: VaultId) -> Self {
        self.id = id;
        self
    }

    /// Set the public name.
    pub fn public_name(mut self, public_name: String) -> Self {
        self.public_name = public_name;
        self
    }

    /// Set the private description.
    pub fn description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    /// Set the flags.
    pub fn flags(mut self, flags: VaultFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Set the cipher.
    pub fn cipher(mut self, cipher: Cipher) -> Self {
        self.cipher = cipher;
        self
    }

    /// Set the key derivation function.
    pub fn kdf(mut self, kdf: KeyDerivation) -> Self {
        self.kdf = kdf;
        self
    }

    /// Build the vault.
    pub async fn build<'a>(
        self,
        credentials: BuilderCredentials<'a>,
    ) -> Result<Vault> {
        let mut vault: Vault = Default::default();
        vault.header.summary.id = self.id;
        vault.header.summary.name = self.public_name;
        vault.header.summary.flags = self.flags;
        vault.header.summary.cipher = self.cipher;
        vault.header.summary.kdf = self.kdf;
        let meta = VaultMeta {
            date_created: Default::default(),
            description: self.description.clone().unwrap_or_default(),
        };

        let private_key = match credentials {
            BuilderCredentials::Password(password, seed) => {
                vault.symmetric(password, seed).await?
            }
            BuilderCredentials::Shared {
                owner,
                recipients,
                read_only,
            } => vault.asymmetric(owner, recipients, read_only).await?,
        };
        encrypt_meta(&mut vault, &private_key, meta).await?;
        Ok(vault)
    }
}

/// Encrypt the meta data and assign to the vault.
async fn encrypt_meta(
    vault: &mut Vault,
    private_key: &PrivateKey,
    meta: VaultMeta,
) -> Result<()> {
    let meta_blob = encode(&meta).await?;
    let meta_aead = vault.encrypt(private_key, &meta_blob).await?;
    vault.set_vault_meta(meta_aead).await?;
    Ok(())
}
