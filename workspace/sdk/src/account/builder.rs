//! Create a new local account.

use crate::{
    constants::{
        DEFAULT_ARCHIVE_VAULT_NAME, DEFAULT_AUTHENTICATOR_VAULT_NAME,
        DEFAULT_CONTACTS_VAULT_NAME,
    },
    crypto::AccessKey,
    encode,
    identity::{FolderKeys, Identity, IdentityVault},
    signer::ecdsa::Address,
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRow, UserData},
        Gatekeeper, Summary, Vault, VaultBuilder, VaultFlags,
    },
    vfs, Paths, Result,
};
use secrecy::SecretString;
use std::{borrow::Cow, collections::HashMap, path::PathBuf};

/// Private information about a new account.
pub struct PrivateNewAccount {
    /// Directory for the new account.
    pub data_dir: Option<PathBuf>,
    /// Address of the account signing key.
    pub address: Address,
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

impl PrivateNewAccount {
    /// Account address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Summary of the default folder.
    pub fn default_folder(&self) -> &Summary {
        self.default_folder.summary()
    }
}

impl<'a> From<&'a PrivateNewAccount> for PublicNewAccount<'a> {
    fn from(value: &'a PrivateNewAccount) -> Self {
        let mut folders = Vec::new();
        if let Some(archive) = &value.archive {
            folders.push(Cow::Borrowed(archive));
        }
        if let Some(authenticator) = &value.authenticator {
            folders.push(Cow::Borrowed(authenticator));
        }
        if let Some(contacts) = &value.contacts {
            folders.push(Cow::Borrowed(contacts));
        }
        Self {
            address: value.address.clone(),
            identity_vault: Cow::Borrowed(&value.identity_vault),
            default_folder: Cow::Borrowed(&value.default_folder),
            folders,
        }
    }
}

/// Public information about a new account that can
/// be sent over the network.
pub struct PublicNewAccount<'a> {
    /// Address of the account signing key.
    pub address: Address,
    /// Identity vault.
    pub identity_vault: Cow<'a, Vault>,
    /// Default folder.
    pub default_folder: Cow<'a, Vault>,
    /// Addtional folders to be imported
    /// into the new account.
    pub folders: Vec<Cow<'a, Vault>>,
}

/// Create a new account.
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
    pub async fn build(self) -> Result<(Vault, PrivateNewAccount)> {
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

        // Prepare the identity vault
        let identity_vault =
            IdentityVault::new(account_name.clone(), passphrase.clone())
                .await?;
        let (address, identity_vault) = identity_vault.into();

        let mut folder_keys = HashMap::new();

        // Authenticate on the newly created identity vault so we
        // can get the signing key for provider communication
        let buffer = encode(&identity_vault).await?;
        let paths = Paths::new_global(Paths::data_dir()?);
        let mut user = Identity::new(paths);
        let key: AccessKey = passphrase.clone().into();
        user.login_buffer(buffer, &key).await?;

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
            keeper.create(&secret_data).await?;

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

        let vault = user.identity()?.vault().clone();
        Ok((
            vault,
            PrivateNewAccount {
                data_dir,
                address,
                identity_vault,
                default_folder,
                archive,
                authenticator,
                contacts,
                folder_keys: FolderKeys(folder_keys),
            },
        ))
    }

    /// Write the identity vault to disc and prepare storage directories.
    async fn write(
        identity_vault: Vault,
        account: PrivateNewAccount,
    ) -> Result<PrivateNewAccount> {
        let address = account.address.to_string();
        let data_dir = if let Some(data_dir) = &account.data_dir {
            data_dir.clone()
        } else {
            Paths::data_dir()?
        };
        let paths = Paths::new(data_dir, &address);
        // Persist the identity vault to disc, MUST re-encode the buffer
        // as we have modified the identity vault
        let identity_vault_file = paths.identity_vault();
        let buffer = encode(&identity_vault).await?;
        vfs::write(identity_vault_file, buffer).await?;

        Ok(account)
    }

    /// Create a new account and write the identity vault to disc.
    pub async fn finish(self) -> Result<PrivateNewAccount> {
        let (identity_vault, account) = self.build().await?;
        Self::write(identity_vault, account).await
    }
}
