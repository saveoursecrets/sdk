//! Create a new local account.

use crate::{
    constants::{
        DEFAULT_ARCHIVE_VAULT_NAME, DEFAULT_AUTHENTICATOR_VAULT_NAME,
        DEFAULT_CONTACTS_VAULT_NAME,
    },
    crypto::AccessKey,
    identity::{FolderKeys, Identity, IdentityFolder},
    signer::ecdsa::Address,
    storage::AccountPack,
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRow, UserData},
        Gatekeeper, Vault, VaultBuilder, VaultFlags,
    },
    Paths, Result,
};
use secrecy::SecretString;
use std::{collections::HashMap, path::PathBuf};

/// Private information about a new account.
pub struct PrivateNewAccount {
    /// Directory for the new account.
    pub data_dir: Option<PathBuf>,
    /// Address of the account signing key.
    pub address: Address,
    /// User identity.
    pub user: Identity,
    /// Identity vault.
    pub identity_vault: Vault,
    /// Default folder.
    pub default_folder: Vault,
    /// Archive folder.
    pub archive: Option<Vault>,
    /// Authenticator folder.
    pub authenticator: Option<Vault>,
    /// Contacts folder.
    pub contacts: Option<Vault>,
    /// Folder access keys.
    pub folder_keys: FolderKeys,
}

impl From<PrivateNewAccount> for AccountPack {
    fn from(mut value: PrivateNewAccount) -> Self {
        let mut folders = vec![value.default_folder];
        if let Some(archive) = value.archive.take() {
            folders.push(archive);
        }
        if let Some(authenticator) = value.authenticator.take() {
            folders.push(authenticator);
        }
        if let Some(contacts) = value.contacts.take() {
            folders.push(contacts);
        }
        Self {
            address: value.address.clone(),
            identity_vault: value.identity_vault,
            folders,
        }
    }
}

/// Create the data for a new account.
pub struct AccountBuilder {
    data_dir: Option<PathBuf>,
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
    pub fn new(
        account_name: String,
        passphrase: SecretString,
        data_dir: Option<PathBuf>,
    ) -> Self {
        Self {
            data_dir,
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
    async fn build(self) -> Result<PrivateNewAccount> {
        let AccountBuilder {
            data_dir,
            account_name,
            passphrase,
            save_passphrase,
            create_archive,
            create_authenticator,
            create_contacts,
            create_file_password,
            mut default_folder_name,
        } = self;

        Paths::scaffold(data_dir.clone()).await?;

        // Prepare the identity folder
        let identity_folder = IdentityFolder::new(
            account_name.clone(),
            passphrase.clone(),
            data_dir.clone(),
        )
        .await?;

        let address = identity_folder.address().clone();

        let mut folder_keys = HashMap::new();

        // Authenticate on the newly created identity vault so we
        // can get the signing key for provider communication
        let paths = if let Some(data_dir) = &data_dir {
            Paths::new(data_dir, address.to_string())
        } else {
            Paths::new(Paths::data_dir()?, address.to_string())
        };

        paths.ensure().await?;

        let mut user = Identity::new(paths.clone());
        let key: AccessKey = passphrase.clone().into();
        user.login(paths.identity_vault(), &key).await?;

        // Prepare the passphrase for the default vault
        let vault_passphrase = user.generate_folder_password()?;

        // Prepare the default vault
        let mut builder = VaultBuilder::new().flags(VaultFlags::DEFAULT);
        if let Some(name) = default_folder_name.take() {
            builder = builder.public_name(name);
        }
        let mut default_folder =
            builder.password(vault_passphrase.clone(), None).await?;

        folder_keys.insert(
            default_folder.summary().clone(),
            vault_passphrase.clone().into(),
        );

        // Save the master passphrase in the default vault
        if save_passphrase {
            let mut keeper = Gatekeeper::new(default_folder);
            let key: AccessKey = vault_passphrase.clone().into();
            keeper.unlock(&key).await?;

            let secret = Secret::Account {
                account: account_name,
                password: passphrase.clone(),
                url: None,
                user_data: UserData::new_comment(address.to_string()),
            };
            let mut meta = SecretMeta::new(
                "Account Password".to_string(),
                secret.kind(),
            );
            meta.set_favorite(true);

            let secret_data =
                SecretRow::new(SecretId::new_v4(), meta, secret);
            keeper.create_secret(&secret_data).await?;

            default_folder = keeper.into();
        }

        user.save_folder_password(
            default_folder.id(),
            AccessKey::Password(vault_passphrase),
        )
        .await?;

        if create_file_password {
            user.create_file_encryption_password().await?;
        }

        let archive = if create_archive {
            let password = user.generate_folder_password()?;
            let vault = VaultBuilder::new()
                .public_name(DEFAULT_ARCHIVE_VAULT_NAME.to_string())
                .flags(VaultFlags::ARCHIVE)
                .password(password.clone(), None)
                .await?;

            folder_keys
                .insert(vault.summary().clone(), password.clone().into());

            user.save_folder_password(vault.id(), password.into())
                .await?;
            Some(vault)
        } else {
            None
        };

        let authenticator = if create_authenticator {
            let password = user.generate_folder_password()?;
            let vault = VaultBuilder::new()
                .public_name(DEFAULT_AUTHENTICATOR_VAULT_NAME.to_string())
                .flags(VaultFlags::AUTHENTICATOR | VaultFlags::NO_SYNC_SELF)
                .password(password.clone(), None)
                .await?;

            folder_keys
                .insert(vault.summary().clone(), password.clone().into());

            user.save_folder_password(vault.id(), password.into())
                .await?;
            Some(vault)
        } else {
            None
        };

        let contacts = if create_contacts {
            let password = user.generate_folder_password()?;
            let vault = VaultBuilder::new()
                .public_name(DEFAULT_CONTACTS_VAULT_NAME.to_string())
                .flags(VaultFlags::CONTACT)
                .password(password.clone(), None)
                .await?;

            folder_keys
                .insert(vault.summary().clone(), password.clone().into());

            user.save_folder_password(vault.id(), password.into())
                .await?;
            Some(vault)
        } else {
            None
        };

        Ok(PrivateNewAccount {
            data_dir,
            address,
            user,
            identity_vault: identity_folder.into(),
            default_folder,
            archive,
            authenticator,
            contacts,
            folder_keys: FolderKeys(folder_keys),
        })
    }

    /// Create a new account and write the identity vault to disc.
    pub async fn finish(self) -> Result<PrivateNewAccount> {
        self.build().await
    }
}
