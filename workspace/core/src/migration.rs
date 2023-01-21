//! Migration defines types that expose all 
//! vaults and secrets insecurely and unencrypted 
//! as a single JSON document for migrating to 
//! another service.

use serde::{Serialize, Deserialize};

use crate::{
    secret::{VaultMeta, SecretId, SecretMeta, Secret},
    vault::Summary,
    Result, Gatekeeper,
};

/// Migration encapsulates a collection of vaults 
/// and their unencrypted secrets.
#[derive(Default, Serialize, Deserialize)]
pub struct PublicMigration {
    vaults: Vec<PublicStore>, 
}

impl PublicMigration {
    /// Add the secrets in a vault to this migration.
    ///
    /// The passed `Gatekeeper` must already be unlocked so the 
    /// secrets can be decrypted.
    pub fn add(&mut self, access: &Gatekeeper) -> Result<()> {
        let meta = access.vault_meta()?;

        let mut store: PublicStore = Default::default();
        store.summary = access.vault().summary().clone();
        store.meta = meta;

        for id in access.vault().keys() {
            if let Some((meta, secret, _)) = access.read(id)? {
                store.secrets.push(PublicSecret {
                    id: *id,
                    meta: meta,
                    secret: secret,
                });
            }
        }

        self.vaults.push(store);
        Ok(())
    }
}

/// Public store is an insecure, unencrypted representation of a vault.
#[derive(Default, Serialize, Deserialize)]
pub struct PublicStore {
    /// The vault summary information.
    summary: Summary,
    /// The vault meta data.
    meta: VaultMeta,
    /// The collection of secrets in the vault.
    secrets: Vec<PublicSecret>
}

/// Public secret is an insecure, unencrypted representation of a secret.
#[derive(Default, Serialize, Deserialize)]
pub struct PublicSecret {
    /// The secret identifier.
    id: SecretId,
    /// The secret meta data.
    meta: SecretMeta,
    /// The secret data.
    secret: Secret,
}

#[cfg(test)]
mod test {

    use anyhow::Result;
    use secrecy::ExposeSecret;

    use super::*;
    use crate::{
        generate_passphrase,
        vault::Vault,
        Gatekeeper,
        test_utils::*,
    };
    
    #[test]
    fn migration_vault() -> Result<()> {
        let (passphrase, _) = generate_passphrase()?;

        let mut vault: Vault = Default::default();
        vault.set_default_flag(true);
        vault.initialize(passphrase.expose_secret())?;

        let mut keeper = Gatekeeper::new(vault, None);
        let mut migration: PublicMigration = Default::default();

        keeper.unlock(passphrase.expose_secret())?;

        let (meta, secret, _, _) = mock_secret_note(
            "Mock note", "Value for the mock note")?;

        keeper.create(meta, secret)?;

        migration.add(&keeper)?;

        let value = serde_json::to_string_pretty(&migration)?;

        println!("{}", value);
        
        Ok(())
    }
}
