use crate::{
    constants::DEFAULT_VAULT_NAME,
    crypto::{Cipher, KeyDerivation, Seed},
    encode,
    vault::{Vault, VaultAccess, VaultFlags, VaultId, VaultMeta},
    Result,
};
use secrecy::SecretString;

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

    /// Prepare a vault.
    fn prepare(self) -> (Vault, VaultMeta) {
        let mut vault: Vault = Default::default();
        vault.header.summary.id = self.id;
        vault.header.summary.name = self.public_name;
        vault.header.summary.flags = self.flags;
        vault.header.summary.cipher = self.cipher;
        vault.header.summary.kdf = self.kdf;
        let meta = VaultMeta {
            date_created: Default::default(),
            description: self.description.unwrap_or_default(),
        };
        (vault, meta)
    }

    /// Build a password protected vault.
    pub async fn password(
        self,
        password: SecretString,
        seed: Option<Seed>,
    ) -> Result<Vault> {
        let (mut vault, meta) = self.prepare();
        let private_key = vault.symmetric(password.clone(), seed).await?;

        let meta_blob = encode(&meta).await?;
        let meta_aead = vault.encrypt(&private_key, &meta_blob).await?;
        vault.set_vault_meta(Some(meta_aead)).await;

        Ok(vault)
    }

    /// Build a shared vault.
    pub async fn shared(
        self,
        _identity: age::x25519::Identity,
    ) -> Result<Vault> {
        let (_vault, _meta) = self.prepare();
        todo!();
        //vault.initialize(password, seed).await?;
        // FIXME: encrypt the meta data
        //Ok(vault)
    }
}
