//! Create a new local account.
use crate::{Error, Result};
use secrecy::SecretString;
use sos_backend::BackendTarget;
use sos_client_storage::AccountPack;
use sos_core::{
    constants::{
        DEFAULT_ARCHIVE_VAULT_NAME, DEFAULT_AUTHENTICATOR_VAULT_NAME,
        DEFAULT_CONTACTS_VAULT_NAME,
    },
    crypto::AccessKey,
    AccountId, Paths, SecretId, VaultFlags, VaultId,
};
use sos_login::{DelegatedAccess, FolderKeys, Identity, IdentityFolder};
use sos_vault::{
    secret::{Secret, SecretMeta, SecretRow},
    AccessPoint, BuilderCredentials, SecretAccess, Vault, VaultBuilder,
};
use std::collections::HashMap;

/// Private information about a new account.
pub struct PrivateNewAccount {
    /// Account identifier.
    pub account_id: AccountId,
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

impl From<PrivateNewAccount> for (Identity, AccountPack) {
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
        (
            value.user,
            AccountPack {
                account_id: value.account_id,
                identity_vault: value.identity_vault,
                folders,
            },
        )
    }
}

/// Create the data for a new account.
pub struct AccountBuilder {
    target: BackendTarget,
    // data_dir: Option<PathBuf>,
    account_id: Option<AccountId>,
    account_name: String,
    passphrase: SecretString,
    save_passphrase: bool,
    create_archive: bool,
    create_authenticator: bool,
    create_contacts: bool,
    create_file_password: bool,
    default_folder_name: Option<String>,
    archive_folder_name: Option<String>,
    authenticator_folder_name: Option<String>,
    contacts_folder_name: Option<String>,
}

impl AccountBuilder {
    /// Create a new account builder.
    pub fn new(
        account_name: String,
        passphrase: SecretString,
        target: BackendTarget,
    ) -> Self {
        Self {
            target,
            account_id: None,
            account_name,
            passphrase,
            save_passphrase: false,
            create_archive: false,
            create_authenticator: false,
            create_contacts: false,
            create_file_password: false,
            default_folder_name: None,
            archive_folder_name: None,
            authenticator_folder_name: None,
            contacts_folder_name: None,
        }
    }

    /// Set the account id.
    pub fn account_id(mut self, value: AccountId) -> Self {
        self.account_id = Some(value);
        self
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
    pub fn default_folder_name(mut self, value: String) -> Self {
        self.default_folder_name = Some(value);
        self
    }

    /// Set the name of the archive folder.
    pub fn archive_folder_name(mut self, value: String) -> Self {
        self.archive_folder_name = Some(value);
        self
    }

    /// Set the name of the authenticator folder.
    pub fn authenticator_folder_name(mut self, value: String) -> Self {
        self.authenticator_folder_name = Some(value);
        self
    }

    /// Set the name of the contacts folder.
    pub fn contacts_folder_name(mut self, value: String) -> Self {
        self.contacts_folder_name = Some(value);
        self
    }

    async fn build_default_folder(
        &mut self,
        user: &mut Identity,
        folder_keys: &mut HashMap<VaultId, AccessKey>,
    ) -> Result<Vault> {
        // Prepare the passphrase for the default vault
        let vault_passphrase = user.generate_folder_password()?;

        // Prepare the default vault
        let mut builder = VaultBuilder::new().flags(VaultFlags::DEFAULT);
        if let Some(name) = self.default_folder_name.take() {
            builder = builder.public_name(name);
        }
        let mut default_folder = builder
            .build(BuilderCredentials::Password(
                vault_passphrase.clone(),
                None,
            ))
            .await?;

        folder_keys
            .insert(*default_folder.id(), vault_passphrase.clone().into());

        // Save the account password in the default vault
        if self.save_passphrase {
            let mut keeper = AccessPoint::<Error>::new(default_folder);
            let key: AccessKey = vault_passphrase.clone().into();
            keeper.unlock(&key).await?;

            let secret = Secret::Account {
                account: self.account_name.clone(),
                password: self.passphrase.clone(),
                url: Default::default(),
                user_data: Default::default(),
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

        Ok(default_folder)
    }

    async fn build_archive(
        &mut self,
        user: &mut Identity,
        folder_keys: &mut HashMap<VaultId, AccessKey>,
    ) -> Result<Option<Vault>> {
        Ok(if self.create_archive {
            let password = user.generate_folder_password()?;
            let vault = VaultBuilder::new()
                .public_name(self.archive_folder_name.take().unwrap_or_else(
                    || DEFAULT_ARCHIVE_VAULT_NAME.to_string(),
                ))
                .flags(VaultFlags::ARCHIVE)
                .build(BuilderCredentials::Password(password.clone(), None))
                .await?;

            folder_keys.insert(*vault.id(), password.clone().into());

            user.save_folder_password(vault.id(), password.into())
                .await?;
            Some(vault)
        } else {
            None
        })
    }

    async fn build_authenticator(
        &mut self,
        user: &mut Identity,
        folder_keys: &mut HashMap<VaultId, AccessKey>,
    ) -> Result<Option<Vault>> {
        Ok(if self.create_authenticator {
            let password = user.generate_folder_password()?;
            let vault = VaultBuilder::new()
                .public_name(
                    self.authenticator_folder_name.take().unwrap_or_else(
                        || DEFAULT_AUTHENTICATOR_VAULT_NAME.to_string(),
                    ),
                )
                .flags(VaultFlags::AUTHENTICATOR)
                .build(BuilderCredentials::Password(password.clone(), None))
                .await?;

            folder_keys.insert(*vault.id(), password.clone().into());

            user.save_folder_password(vault.id(), password.into())
                .await?;
            Some(vault)
        } else {
            None
        })
    }

    async fn build_contacts(
        &mut self,
        user: &mut Identity,
        folder_keys: &mut HashMap<VaultId, AccessKey>,
    ) -> Result<Option<Vault>> {
        Ok(if self.create_contacts {
            let password = user.generate_folder_password()?;
            let vault = VaultBuilder::new()
                .public_name(self.contacts_folder_name.take().unwrap_or_else(
                    || DEFAULT_CONTACTS_VAULT_NAME.to_string(),
                ))
                .flags(VaultFlags::CONTACT)
                .build(BuilderCredentials::Password(password.clone(), None))
                .await?;

            folder_keys.insert(*vault.id(), password.clone().into());

            user.save_folder_password(vault.id(), password.into())
                .await?;
            Some(vault)
        } else {
            None
        })
    }

    /// Create a new account and write the identity
    /// folder to backend storage.
    pub async fn finish(mut self) -> Result<PrivateNewAccount> {
        // TODO: remove this and always scaffold in test specs
        #[cfg(debug_assertions)]
        if let BackendTarget::FileSystem(paths) = &self.target {
            Paths::scaffold(Some(paths.documents_dir().to_owned())).await?;
        }

        // Prepare the identity folder
        let identity_folder = IdentityFolder::new(
            self.target.clone(),
            self.account_name.clone(),
            self.passphrase.clone(),
            self.account_id.clone(),
        )
        .await?;

        let account_id = *identity_folder.account_id();
        let paths = self.target.paths().with_account_id(&account_id);

        match &self.target {
            BackendTarget::FileSystem(_) => {
                paths.ensure().await?;
            }
            BackendTarget::Database(_, _) => {
                paths.ensure_db().await?;
            }
        }

        let mut user = Identity::new(self.target.clone());
        let key: AccessKey = self.passphrase.clone().into();
        user.login(&account_id, &key).await?;

        let mut folder_keys = HashMap::new();
        let default_folder = self
            .build_default_folder(&mut user, &mut folder_keys)
            .await?;

        #[cfg(feature = "files")]
        if self.create_file_password {
            user.create_file_encryption_password().await?;
        }

        let archive = self.build_archive(&mut user, &mut folder_keys).await?;
        let authenticator = self
            .build_authenticator(&mut user, &mut folder_keys)
            .await?;
        let contacts =
            self.build_contacts(&mut user, &mut folder_keys).await?;

        Ok(PrivateNewAccount {
            account_id,
            user,
            identity_vault: identity_folder.into(),
            default_folder,
            archive,
            authenticator,
            contacts,
            folder_keys: FolderKeys(folder_keys),
        })
    }
}
