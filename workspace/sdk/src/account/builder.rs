//! Create new local account.

use urn::Urn;

use crate::{
    constants::FILE_PASSWORD_URN,
    encode,
    storage::StorageDirs,
    vault::{
        secret::{Secret, SecretMeta, UserData},
        Gatekeeper, Summary, Vault,
    },
    Result,
};
use web3_address::ethereum::Address;

use super::{DelegatedPassphrase, Identity, UserIdentity};

use secrecy::SecretString;

/// Newly created account information.
pub struct NewAccount {
    /// Address of the account signing key.
    pub address: Address,
    /// Authenticated user.
    pub user: UserIdentity,
    /// Default vault.
    pub default_vault: Vault,
    /// Archive vault.
    pub archive: Option<Vault>,
    /// Authenticator vault.
    pub authenticator: Option<Vault>,
    /// Contacts vault.
    pub contacts: Option<Vault>,
}

/// New account vaults that have been imported into
/// a storage provider.
pub struct ImportedAccount {
    /// Summary for the default folder.
    pub summary: Summary,
    /// Sumary for an archive if the new account
    /// includes an archive folder.
    pub archive: Option<Summary>,
    /// Sumary for an authenticator if the new account
    /// includes an authenticator folder.
    pub authenticator: Option<Summary>,
    /// Sumary for contacts if the new account
    /// includes a contacts folder.
    pub contacts: Option<Summary>,
}

/// Create a new account.
pub struct AccountBuilder {
    account_name: String,
    passphrase: SecretString,
    save_passphrase: bool,
    create_archive: bool,
    create_authenticator: bool,
    create_contacts: bool,
    create_file_password: bool,
    default_folder_name: Option<String>,
}

impl AccountBuilder {
    /// Create a new account builder.
    pub fn new(account_name: String, passphrase: SecretString) -> Self {
        Self {
            account_name,
            passphrase,
            save_passphrase: false,
            create_archive: false,
            create_authenticator: false,
            create_contacts: false,
            create_file_password: false,
            default_folder_name: None,
        }
    }

    /// Enable saving the master passphrase in the default folder.
    pub fn save_passphrase(mut self, value: bool) -> Self {
        self.save_passphrase = value;
        self
    }

    /// Enable creating an archive folder.
    pub fn create_archive(mut self, value: bool) -> Self {
        self.create_archive = value;
        self
    }

    /// Enable creating an authenticator folder.
    pub fn create_authenticator(mut self, value: bool) -> Self {
        self.create_authenticator = value;
        self
    }

    /// Enable creating an contacts folder.
    pub fn create_contacts(mut self, value: bool) -> Self {
        self.create_contacts = value;
        self
    }

    /// Enable creating a password for symmetric file encryption.
    pub fn create_file_password(mut self, value: bool) -> Self {
        self.create_file_password = value;
        self
    }

    /// Set the name of the default folder.
    pub fn default_folder_name(mut self, value: Option<String>) -> Self {
        self.default_folder_name = value;
        self
    }

    /// Create a new identity vault and account folders.
    pub fn build(self) -> Result<(Vault, NewAccount)> {
        let AccountBuilder {
            account_name,
            passphrase,
            save_passphrase,
            create_archive,
            create_authenticator,
            create_contacts,
            create_file_password,
            mut default_folder_name,
        } = self;

        // Prepare the identity vault
        let (address, identity_vault) = Identity::new_login_vault(
            account_name.clone(),
            passphrase.clone(),
        )?;

        // Authenticate on the newly created identity vault so we
        // can get the signing key for provider communication
        let buffer = encode(&identity_vault)?;
        let user =
            Identity::login_buffer(buffer, passphrase.clone(), None, None)?;

        // Prepare the passphrase for the default vault
        let vault_passphrase =
            DelegatedPassphrase::generate_vault_passphrase()?;

        // Prepare the default vault
        let mut default_vault: Vault = Default::default();
        if let Some(name) = default_folder_name.take() {
            default_vault.set_name(name);
        }
        default_vault.set_default_flag(true);
        default_vault.initialize(vault_passphrase.clone(), None)?;

        // Save the master passphrase in the default vault
        if save_passphrase {
            let mut keeper = Gatekeeper::new(default_vault, None);
            keeper.unlock(vault_passphrase.clone())?;

            let secret = Secret::Account {
                account: account_name,
                password: passphrase.clone(),
                url: None,
                user_data: UserData::new_comment(address.to_string()),
            };
            let mut meta =
                SecretMeta::new("Master Password".to_string(), secret.kind());
            meta.set_favorite(true);
            keeper.create(meta, secret)?;

            default_vault = keeper.into();
        }

        // Store the vault passphrase in the identity vault
        let mut keeper = Gatekeeper::new(identity_vault, None);
        keeper.unlock(passphrase)?;

        DelegatedPassphrase::save_vault_passphrase(
            &mut keeper,
            default_vault.id(),
            vault_passphrase,
        )?;

        if create_file_password {
            let file_passphrase =
                DelegatedPassphrase::generate_vault_passphrase()?;
            let secret = Secret::Password {
                password: file_passphrase,
                name: None,
                user_data: UserData::new_comment(address.to_string()),
            };
            let mut meta =
                SecretMeta::new("File Encryption".to_string(), secret.kind());
            let urn: Urn = FILE_PASSWORD_URN.parse()?;
            meta.set_urn(Some(urn));
            keeper.create(meta, secret)?;
        }

        let archive = if create_archive {
            // Prepare the passphrase for the archive vault
            let archive_passphrase =
                DelegatedPassphrase::generate_vault_passphrase()?;

            // Prepare the archive vault
            let mut vault: Vault = Default::default();
            vault.set_name("Archive".to_string());
            vault.set_archive_flag(true);
            vault.initialize(archive_passphrase.clone(), None)?;
            DelegatedPassphrase::save_vault_passphrase(
                &mut keeper,
                vault.id(),
                archive_passphrase,
            )?;
            Some(vault)
        } else {
            None
        };

        let authenticator = if create_authenticator {
            // Prepare the passphrase for the authenticator vault
            let auth_passphrase =
                DelegatedPassphrase::generate_vault_passphrase()?;

            // Prepare the authenticator vault
            let mut vault: Vault = Default::default();
            vault.set_name("Authenticator".to_string());
            vault.set_authenticator_flag(true);
            vault.set_no_sync_self_flag(true);
            vault.initialize(auth_passphrase.clone(), None)?;
            DelegatedPassphrase::save_vault_passphrase(
                &mut keeper,
                vault.id(),
                auth_passphrase,
            )?;
            Some(vault)
        } else {
            None
        };

        let contacts = if create_contacts {
            // Prepare the passphrase for the authenticator vault
            let auth_passphrase =
                DelegatedPassphrase::generate_vault_passphrase()?;

            // Prepare the authenticator vault
            let mut vault: Vault = Default::default();
            vault.set_name("Contacts".to_string());
            vault.set_contact_flag(true);
            vault.initialize(auth_passphrase.clone(), None)?;
            DelegatedPassphrase::save_vault_passphrase(
                &mut keeper,
                vault.id(),
                auth_passphrase,
            )?;
            Some(vault)
        } else {
            None
        };

        Ok((
            keeper.into(),
            NewAccount {
                address,
                user,
                default_vault,
                archive,
                authenticator,
                contacts,
            },
        ))
    }

    #[cfg(not(target_arch = "wasm32"))]
    /// Write the identity vault to disc and prepare storage directories.
    pub fn write(
        identity_vault: Vault,
        account: NewAccount,
    ) -> Result<NewAccount> {
        let address = account.address.to_string();
        // Persist the identity vault to disc, MUST re-encode the buffer
        // as we have modified the identity vault
        let identity_vault_file = StorageDirs::identity_vault(&address)?;
        let buffer = encode(&identity_vault)?;
        std::fs::write(identity_vault_file, buffer)?;

        // Ensure the files directory exists
        StorageDirs::files_dir(&address)?;

        Ok(account)
    }

    /// Create a new account and write the identity vault to disc.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn finish(self) -> Result<NewAccount> {
        let (identity_vault, account) = self.build()?;
        Self::write(identity_vault, account)
    }
}
