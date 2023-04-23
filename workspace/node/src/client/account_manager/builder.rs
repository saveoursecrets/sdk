//! Account manager provides utility functions for
//! creating and managing local accounts.
use std::{
    borrow::Cow,
    fs::File,
    io::Cursor,
    path::{Path, PathBuf},
    sync::Arc,
};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use urn::Urn;
use uuid::Uuid;
use walkdir::WalkDir;

use sos_core::{
    archive::{Inventory, Reader, Writer},
    constants::{DEVICE_KEY_URN, FILE_PASSWORD_URN, VAULT_EXT, WAL_EXT},
    decode, encode,
    events::WalEvent,
    identity::{AuthenticatedUser, Identity},
    passwd::{diceware::generate_passphrase_words, ChangePassword},
    search::SearchIndex,
    sha2::{Digest, Sha256},
    signer::{
        ecdsa::SingleParty,
        ed25519::{self, BoxedEd25519Signer},
        Signer,
    },
    storage::StorageDirs,
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretSigner, UserData},
        Gatekeeper, Header, Summary, Vault, VaultAccess, VaultFileAccess,
        VaultId,
    },
    wal::{file::WalFile, WalProvider},
};

use crate::client::{
    provider::{
        BoxedProvider, ProviderFactory, RestoreOptions, RestoreTargets,
    },
    Error, Result,
};

use secrecy::{ExposeSecret, SecretString};

/// Request to create a new account.
pub struct NewAccountRequest {
    /// The name of the account.
    pub account_name: String,
    /// The passphrase for the new account.
    pub passphrase: SecretString,
    /// Whether to save the account passphrase in the default folder.
    pub save_passphrase: bool,
    /// Whether to create a vault to use as an archive folder.
    pub create_archive: bool,
    /// Whether to create a vault to use for two-factor authentication.
    pub create_authenticator: bool,
    /// Whether to create a vault to use for contacts.
    pub create_contact: bool,
    /// Whether to create a password entry in the identity vault
    /// for file encryption.
    pub create_file_password: bool,
    /// Default folder name.
    pub default_folder_name: Option<String>,
}

/// Response to creating a new account.
pub struct NewAccountResponse {
    /// Address of the account signing key.
    pub address: String,
    /// Authenticated user.
    pub user: AuthenticatedUser,
    /// Default vault.
    pub default_vault: Vault,
    /// Default vault summary.
    pub summary: Summary,
    /// Archive summary.
    pub archive: Option<Summary>,
    /// Authenticator summary.
    pub authenticator: Option<Summary>,
    /// Contact summary.
    pub contact: Option<Summary>,
}

/// Manage accounts using the file system and a local provider.
#[derive(Default)]
pub struct AccountManager {}

impl AccountManager {
    /// Create a new account.
    pub async fn new_account(
        account: NewAccountRequest,
    ) -> Result<NewAccountResponse> {
        let NewAccountRequest {
            account_name,
            passphrase,
            save_passphrase,
            create_archive,
            create_authenticator,
            create_contact,
            create_file_password,
            mut default_folder_name,
        } = account;

        // Prepare the identity vault
        let (address, identity_vault) = Identity::new_login_vault(
            account_name.clone(),
            passphrase.clone(),
        )?;

        // Authenticate on the newly created identity vault so we
        // can get the signing key for provider communication
        let buffer = encode(&identity_vault)?;
        let (user, _) =
            Identity::login_buffer(buffer, passphrase.clone(), None, None)?;

        // Prepare the passphrase for the default vault
        let vault_passphrase = Self::generate_vault_passphrase()?;

        // Prepare the default vault
        let mut default_vault: Vault = Default::default();
        if let Some(name) = default_folder_name.take() {
            default_vault.set_name(name);
        }
        default_vault.set_default_flag(true);
        default_vault.initialize(vault_passphrase.expose_secret(), None)?;

        // Save the master passphrase in the default vault
        if save_passphrase {
            let mut keeper = Gatekeeper::new(default_vault, None);
            keeper.unlock(vault_passphrase.expose_secret())?;

            let secret = Secret::Account {
                account: account_name,
                password: passphrase.clone(),
                url: None,
                user_data: UserData::new_comment(address.to_owned()),
            };
            let mut meta =
                SecretMeta::new("Master Password".to_string(), secret.kind());
            meta.set_favorite(true);
            keeper.create(meta, secret)?;

            default_vault = keeper.into();
        }

        // Store the vault passphrase in the identity vault
        let mut keeper = Gatekeeper::new(identity_vault, None);
        keeper.unlock(passphrase.expose_secret())?;

        Self::save_vault_passphrase(
            &mut keeper,
            default_vault.id(),
            vault_passphrase,
        )?;

        if create_file_password {
            let file_passphrase = Self::generate_vault_passphrase()?;
            let secret = Secret::Password {
                password: file_passphrase,
                name: None,
                user_data: UserData::new_comment(address.to_owned()),
            };
            let mut meta =
                SecretMeta::new("File Encryption".to_string(), secret.kind());
            let urn: Urn = FILE_PASSWORD_URN.parse()?;
            meta.set_urn(Some(urn));
            keeper.create(meta, secret)?;
        }

        let archive = if create_archive {
            // Prepare the passphrase for the archive vault
            let archive_passphrase = Self::generate_vault_passphrase()?;

            // Prepare the archive vault
            let mut vault: Vault = Default::default();
            vault.set_name("Archive".to_string());
            vault.set_archive_flag(true);
            vault.initialize(archive_passphrase.expose_secret(), None)?;
            Self::save_vault_passphrase(
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
            let auth_passphrase = Self::generate_vault_passphrase()?;

            // Prepare the authenticator vault
            let mut vault: Vault = Default::default();
            vault.set_name("Authenticator".to_string());
            vault.set_authenticator_flag(true);
            vault.set_no_sync_self_flag(true);
            vault.initialize(auth_passphrase.expose_secret(), None)?;
            Self::save_vault_passphrase(
                &mut keeper,
                vault.id(),
                auth_passphrase,
            )?;
            Some(vault)
        } else {
            None
        };

        let contact = if create_contact {
            // Prepare the passphrase for the authenticator vault
            let auth_passphrase = Self::generate_vault_passphrase()?;

            // Prepare the authenticator vault
            let mut vault: Vault = Default::default();
            vault.set_name("Contacts".to_string());
            vault.set_contact_flag(true);
            vault.initialize(auth_passphrase.expose_secret(), None)?;
            Self::save_vault_passphrase(
                &mut keeper,
                vault.id(),
                auth_passphrase,
            )?;
            Some(vault)
        } else {
            None
        };

        // Persist the identity vault to disc, MUST re-encode the buffer
        // as we have modified the identity vault
        let identity_vault_file = StorageDirs::identity_vault(&address)?;
        let buffer = encode(keeper.vault())?;
        std::fs::write(identity_vault_file, buffer)?;

        // Create local provider
        let factory = ProviderFactory::Local;
        let (mut provider, _) =
            factory.create_provider(user.signer.clone())?;

        // Save the default vault
        let buffer = encode(&default_vault)?;
        let summary = provider.create_account_with_buffer(buffer).await?;

        let archive = if let Some(archive_vault) = archive {
            let buffer = encode(&archive_vault)?;
            let summary = provider.import_vault(buffer).await?;
            Some(summary)
        } else {
            None
        };

        let authenticator = if let Some(authenticator_vault) = authenticator {
            let buffer = encode(&authenticator_vault)?;
            let summary = provider.import_vault(buffer).await?;
            Some(summary)
        } else {
            None
        };

        let contact = if let Some(contact_vault) = contact {
            let buffer = encode(&contact_vault)?;
            let summary = provider.import_vault(buffer).await?;
            Some(summary)
        } else {
            None
        };

        // Ensure the files directory exists
        StorageDirs::files_dir(&address)?;

        Ok(NewAccountResponse {
            address,
            user,
            default_vault,
            summary,
            archive,
            authenticator,
            contact,
        })
    }
}
