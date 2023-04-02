//! Account manager provides utility functions for
//! creating and managing local accounts.
use std::{
    borrow::Cow,
    io::{Cursor, Read},
    path::{Path, PathBuf},
    sync::Arc,
};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use urn::Urn;

use age::Encryptor;
use sha3::{Digest, Sha3_256};

use sos_core::{
    archive::{Inventory, Reader, Writer},
    constants::{
        FILES_DIR, FILE_PASSWORD_URN, IDENTITY_DIR, LOCAL_DIR, VAULTS_DIR,
        VAULT_EXT, WAL_EXT,
    },
    decode, encode,
    events::WalEvent,
    generate_passphrase_words,
    identity::{AuthenticatedUser, Identity},
    search::SearchIndex,
    secret::{Secret, SecretMeta, UserData},
    signer::SingleParty,
    vault::{Header, Summary, Vault, VaultAccess, VaultId},
    wal::{file::WalFile, WalProvider},
    ChangePassword, Gatekeeper, VaultFileAccess,
};

use crate::{
    cache_dir,
    client::{
        provider::{
            BoxedProvider, ProviderFactory, RestoreOptions, RestoreTargets,
        },
        run_blocking, Error, Result,
    },
};

use secrecy::{ExposeSecret, SecretString};

/// Number of words to use when generating passphrases for vaults.
const VAULT_PASSPHRASE_WORDS: usize = 12;

/// Combines an account address with a label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    /// Address identifier for the account.
    ///
    /// This corresponds to the address of the signing key
    /// for the account.
    pub address: String,
    /// User label for the account.
    ///
    /// This is the name given to the identity vault.
    pub label: String,
}

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
}

/// Response to creating a new account.
pub struct NewAccountResponse {
    /// Address of the account signing key.
    pub address: String,
    /// Authenticated user.
    pub user: AuthenticatedUser,
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
    pub fn new_account(
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
            Identity::login_buffer(&buffer, passphrase.clone(), None, None)?;

        // Prepare the passphrase for the default vault
        let vault_passphrase = Self::generate_vault_passphrase()?;

        // Prepare the default vault
        let mut default_vault: Vault = Default::default();
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

            default_vault = keeper.take();
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
        let identity_vault_file = Self::identity_vault(&address)?;
        let buffer = encode(keeper.vault())?;
        std::fs::write(identity_vault_file, &buffer)?;

        // Create local provider
        let factory = ProviderFactory::Local;
        let (mut provider, _) =
            factory.create_provider(user.signer.clone())?;
        run_blocking(provider.authenticate())?;

        // Save the default vault
        let buffer = encode(&default_vault)?;
        let summary =
            run_blocking(provider.create_account_with_buffer(buffer))?;

        let archive = if let Some(archive_vault) = archive {
            let buffer = encode(&archive_vault)?;
            let summary = run_blocking(provider.import_vault(buffer))?;
            Some(summary)
        } else {
            None
        };

        let authenticator = if let Some(authenticator_vault) = authenticator {
            let buffer = encode(&authenticator_vault)?;
            let summary = run_blocking(provider.import_vault(buffer))?;
            Some(summary)
        } else {
            None
        };

        let contact = if let Some(contact_vault) = contact {
            let buffer = encode(&contact_vault)?;
            let summary = run_blocking(provider.import_vault(buffer))?;
            Some(summary)
        } else {
            None
        };

        // Ensure the files directory exists
        Self::files_dir(&address)?;

        Ok(NewAccountResponse {
            address,
            user,
            summary,
            archive,
            authenticator,
            contact,
        })
    }

    /// Encrypt a file using AGE passphrase encryption and
    /// move to the external storage location.
    ///
    /// The file name is the Sha256 digest of the original file.
    pub fn encrypt_file<P: AsRef<Path>>(
        address: &str,
        path: P,
        passphrase: SecretString,
    ) -> Result<Vec<u8>> {
        let mut file = std::fs::File::open(path)?;
        let encryptor = Encryptor::with_user_passphrase(passphrase);

        let mut hasher = Sha3_256::new();
        let mut encrypted = tempfile::NamedTempFile::new()?;

        let mut writer = encryptor.wrap_output(&mut encrypted)?;
        std::io::copy(&mut file, &mut writer)?;
        std::io::copy(&mut file, &mut hasher)?;
        writer.finish()?;

        let digest = hasher.finalize();
        let file_name = hex::encode(digest);
        let dest = Self::files_dir(address)?.join(&file_name);
        
        // Move the temporary file into place
        std::fs::rename(encrypted.path(), dest)?;

        Ok(digest.to_vec())
    }

    /// Decrypt a file using AGE passphrase encryption.
    pub fn decrypt_file<P: AsRef<Path>>(
        path: P,
        passphrase: SecretString,
    ) -> Result<Vec<u8>> {
        let file = std::fs::File::open(path)?;
        let decryptor = match age::Decryptor::new(file)? {
            age::Decryptor::Passphrase(d) => d,
            _ => return Err(Error::NotPassphraseEncryption),
        };

        let mut decrypted = vec![];
        let mut reader = decryptor.decrypt(&passphrase, None)?;
        reader.read_to_end(&mut decrypted)?;
        
        Ok(decrypted)
    }

    /// Get the local cache directory.
    pub fn local_dir() -> Result<PathBuf> {
        let local_dir = cache_dir().ok_or(Error::NoCache)?.join(LOCAL_DIR);
        Ok(local_dir)
    }

    /// Get the local directory for storing vaults.
    pub fn local_vaults_dir(address: &str) -> Result<PathBuf> {
        let local_dir = Self::local_dir()?;
        let vaults_dir = local_dir.join(address).join(VAULTS_DIR);
        Ok(vaults_dir)
    }

    /// Get the path to the directory used to store files.
    ///
    /// Ensure it exists if it does not already exist.
    pub fn files_dir(address: &str) -> Result<PathBuf> {
        let local_dir = Self::local_dir()?;
        let files_dir = local_dir.join(address).join(FILES_DIR);
        if !files_dir.exists() {
            std::fs::create_dir(&files_dir)?;
        }
        Ok(files_dir)
    }

    /// Generate a vault passphrase.
    pub fn generate_vault_passphrase() -> Result<SecretString> {
        let (vault_passphrase, _) =
            generate_passphrase_words(VAULT_PASSPHRASE_WORDS)?;
        Ok(vault_passphrase)
    }

    /// Save a vault passphrase into an identity vault.
    pub fn save_vault_passphrase(
        identity: &mut Gatekeeper,
        vault_id: &VaultId,
        vault_passphrase: SecretString,
    ) -> Result<()> {
        let urn = Vault::vault_urn(vault_id)?;

        let secret = Secret::Password {
            name: None,
            password: vault_passphrase,
            user_data: Default::default(),
        };
        let mut meta =
            SecretMeta::new(urn.as_str().to_owned(), secret.kind());
        meta.set_urn(Some(urn));
        identity.create(meta, secret)?;
        Ok(())
    }

    /// Remove a vault passphrase from an identity vault.
    pub fn remove_vault_passphrase(
        identity: &mut Gatekeeper,
        vault_id: &VaultId,
    ) -> Result<()> {
        let urn = Vault::vault_urn(vault_id)?;
        let index = identity.index();
        let index_reader = index.read();
        let document = index_reader
            .find_by_urn(identity.id(), &urn)
            .ok_or(Error::NoVaultEntry(urn.to_string()))?;

        let id = *document.id();

        // Must drop the index reader as deleting
        // will write to the index
        drop(index_reader);

        identity.delete(&id)?;

        Ok(())
    }

    /// Find a vault passphrase in an identity vault using the
    /// search index associated with the vault.
    ///
    /// The identity vault must already be unlocked to extract
    /// the secret passphrase.
    pub fn find_vault_passphrase(
        identity: &Gatekeeper,
        vault_id: &VaultId,
    ) -> Result<SecretString> {
        let urn = Vault::vault_urn(vault_id)?;
        let index = identity.index();
        let index_reader = index.read();
        let document = index_reader
            .find_by_urn(identity.id(), &urn)
            .ok_or_else(|| Error::NoVaultEntry(urn.to_string()))?;

        let (_, secret, _) = identity
            .read(document.id())?
            .ok_or_else(|| Error::NoVaultEntry(document.id().to_string()))?;

        let passphrase = if let Secret::Password { password, .. } = secret {
            password
        } else {
            return Err(Error::VaultEntryKind(urn.to_string()));
        };

        Ok(passphrase)
    }

    /// Sign in a user.
    pub fn sign_in(
        address: String,
        passphrase: SecretString,
        index: Arc<RwLock<SearchIndex>>,
    ) -> Result<(AccountInfo, AuthenticatedUser, Gatekeeper)> {
        let accounts = Self::list_accounts()?;
        let account = accounts
            .into_iter()
            .find(|a| a.address == address)
            .ok_or_else(|| Error::NoAccount(address.clone()))?;

        let identity_path = Self::identity_vault(&address)?;
        let (user, keeper) =
            Identity::login_file(identity_path, passphrase, Some(index))?;

        Ok((account, user, keeper))
    }

    /// Verify the master passphrase for an account.
    pub fn verify(address: &str, passphrase: SecretString) -> Result<bool> {
        let identity_path = Self::identity_vault(&address)?;
        let result = Identity::login_file(identity_path, passphrase, None);
        Ok(result.is_ok())
    }

    /// Get the path to the directory used to store identity vaults.
    ///
    /// Ensure it exists if it does not already exist.
    pub fn identity_dir() -> Result<PathBuf> {
        let cache_dir = cache_dir().ok_or(Error::NoCache)?;
        let identity_dir = cache_dir.join(IDENTITY_DIR);
        if !identity_dir.exists() {
            std::fs::create_dir(&identity_dir)?;
        }
        Ok(identity_dir)
    }

    /// Get the path to the identity vault file for an account identifier.
    pub fn identity_vault(address: &str) -> Result<PathBuf> {
        let identity_dir = Self::identity_dir()?;
        let mut identity_vault_file = identity_dir.join(address);
        identity_vault_file.set_extension(VAULT_EXT);
        Ok(identity_vault_file)
    }

    /// Rename an identity vault.
    ///
    /// The caller should take care to ensure this is only allowed on the
    /// identity vault for the currently authenticated account.
    pub fn rename_identity(
        address: &str,
        account_name: String,
    ) -> Result<()> {
        let identity_vault_file = Self::identity_vault(address)?;
        let mut access = VaultFileAccess::new(&identity_vault_file)?;
        access.set_vault_name(account_name)?;
        Ok(())
    }

    /// Permanently delete the identity vault and local vaults for an account.
    pub fn delete_account(address: &str) -> Result<()> {
        let identity_vault_file = Self::identity_vault(address)?;

        let local_dir = Self::local_dir()?;
        let identity_data_dir = local_dir.join(address);

        // FIXME: move to a trash folder
        std::fs::remove_file(&identity_vault_file)?;
        std::fs::remove_dir_all(&identity_data_dir)?;

        Ok(())
    }

    /// Export a vault by changing the vault passphrase and
    /// converting it to a buffer.
    ///
    /// The identity vault must be unlocked so we can retrieve
    /// the passphrase for the target vault.
    pub fn export_vault(
        address: &str,
        identity: &Gatekeeper,
        vault_id: &VaultId,
        new_passphrase: SecretString,
    ) -> Result<Vec<u8>> {
        // Get the current vault passphrase from the identity vault
        let current_passphrase =
            Self::find_vault_passphrase(identity, vault_id)?;

        // Find the local vault for the account
        let (vault, _) = Self::find_local_vault(address, vault_id)?;

        // Change the password before exporting
        let (_, vault, _) = ChangePassword::new(
            &vault,
            current_passphrase,
            new_passphrase,
            None,
        )
        .build()?;

        Ok(encode(&vault)?)
    }

    /// Find and load a vault for a local file.
    pub fn find_local_vault(
        address: &str,
        id: &VaultId,
    ) -> Result<(Vault, PathBuf)> {
        let vaults = Self::list_local_vaults(address)?;
        let (_summary, path) = vaults
            .into_iter()
            .find(|(s, _)| s.id() == id)
            .ok_or_else(|| Error::NoVaultFile(id.to_string()))?;

        let buffer = std::fs::read(&path)?;
        let vault: Vault = decode(&buffer)?;
        Ok((vault, path))
    }

    /// Find the default vault for an account.
    pub fn find_default_vault(address: &str) -> Result<(Summary, PathBuf)> {
        let vaults = Self::list_local_vaults(address)?;
        let (summary, path) = vaults
            .into_iter()
            .find(|(s, _)| s.flags().is_default())
            .ok_or_else(|| Error::NoDefaultVault(address.to_string()))?;
        Ok((summary, path))
    }

    /// Get a list of the vaults for an account directly from the file system.
    pub fn list_local_vaults(
        address: &str,
    ) -> Result<Vec<(Summary, PathBuf)>> {
        let vaults_dir = Self::local_vaults_dir(address)?;
        let mut vaults = Vec::new();
        for entry in std::fs::read_dir(vaults_dir)? {
            let entry = entry?;
            if let Some(extension) = entry.path().extension() {
                if extension == VAULT_EXT {
                    let summary = Header::read_summary_file(entry.path())?;
                    vaults.push((summary, entry.path().to_path_buf()));
                }
            }
        }
        Ok(vaults)
    }

    /// Create a buffer for a gzip compressed tarball including the
    /// identity vault and all user vaults.
    pub fn export_archive_buffer(address: &str) -> Result<Vec<u8>> {
        let identity_path = Self::identity_vault(address)?;
        if !identity_path.exists() {
            return Err(Error::NotFile(identity_path));
        }
        let identity = std::fs::read(identity_path)?;

        let vaults = Self::list_local_vaults(address)?;

        let mut archive = Vec::new();
        let writer = Writer::new(Cursor::new(&mut archive));
        let mut writer =
            writer.set_identity(address.to_owned(), &identity)?;

        for (summary, path) in vaults {
            let buffer = std::fs::read(path)?;
            writer = writer.add_vault(*summary.id(), &buffer)?;
        }

        writer.finish()?;
        Ok(archive)
    }

    /// Export an archive of the account to disc.
    pub fn export_archive_file<P: AsRef<Path>>(
        path: P,
        address: &str,
    ) -> Result<()> {
        let buffer = Self::export_archive_buffer(address)?;
        std::fs::write(path.as_ref(), buffer)?;
        Ok(())
    }

    /// Read the inventory from an archive.
    pub fn restore_archive_inventory(
        mut archive: Vec<u8>,
    ) -> Result<Inventory> {
        let mut reader = Reader::new(Cursor::new(&mut archive))?;
        Ok(reader.inventory()?)
    }

    /// List account information for the identity vaults.
    pub fn list_accounts() -> Result<Vec<AccountInfo>> {
        let mut keys = Vec::new();
        let identity_dir = Self::identity_dir()?;
        for entry in std::fs::read_dir(identity_dir)? {
            let entry = entry?;
            if let (Some(extension), Some(file_stem)) =
                (entry.path().extension(), entry.path().file_stem())
            {
                if extension == VAULT_EXT {
                    let summary = Header::read_summary_file(entry.path())?;
                    keys.push(AccountInfo {
                        address: file_stem.to_string_lossy().into_owned(),
                        label: summary.name().to_owned(),
                    });
                }
            }
        }
        keys.sort_by(|a, b| a.label.cmp(&b.label));
        Ok(keys)
    }

    /// Import from an archive.
    pub fn restore_archive_buffer(
        buffer: Vec<u8>,
        options: RestoreOptions,
        provider: Option<&mut BoxedProvider>,
    ) -> Result<AccountInfo> {
        // FIXME: ensure we still have ONE vault marked as default vault!!!

        // Signed in so use the existing provider
        let account = if let Some(provider) = provider {
            let targets =
                provider.extract_verify_archive(buffer, &options)?;

            let RestoreTargets {
                address,
                identity,
                vaults,
            } = &targets;

            // The GUI should check the identity already exists
            // but we will double check here to be safe
            let keys = Self::list_accounts()?;
            let existing_key = keys.iter().find(|k| &k.address == address);
            let account = existing_key
                .ok_or_else(|| Error::NoArchiveAccount(address.to_owned()))?
                .clone();

            if let Some(passphrase) = &options.passphrase {
                let identity_vault_file = Self::identity_vault(&address)?;
                let identity_buffer = std::fs::read(&identity_vault_file)?;
                let identity_vault: Vault = decode(&identity_buffer)?;
                let mut identity_keeper =
                    Gatekeeper::new(identity_vault, None);
                identity_keeper.unlock(passphrase.expose_secret())?;

                let search_index =
                    Arc::new(RwLock::new(SearchIndex::new(None)));
                let restored_identity: Vault = decode(&identity.1)?;
                let mut restored_identity_keeper = Gatekeeper::new(
                    restored_identity,
                    Some(Arc::clone(&search_index)),
                );
                restored_identity_keeper
                    .unlock(passphrase.expose_secret())?;
                restored_identity_keeper.create_search_index()?;

                for (_, vault) in vaults {
                    let vault_passphrase = Self::find_vault_passphrase(
                        &mut restored_identity_keeper,
                        vault.id(),
                    )?;

                    Self::save_vault_passphrase(
                        &mut identity_keeper,
                        vault.id(),
                        vault_passphrase,
                    )?;
                }

                // Must re-write the identity vault
                let buffer = encode(identity_keeper.vault())?;
                std::fs::write(identity_vault_file, &buffer)?;
            }

            run_blocking(provider.restore_archive(&targets))?;

            account
        // No provider available so the user is not signed in
        } else {
            // Create a mock provider so we can use the extract_verify_archive()
            // function declared on the StorageProvider trait
            let signer = Box::new(SingleParty::new_random());
            let factory = ProviderFactory::Local;
            let (provider, _) = factory.create_provider(signer)?;
            let restore_targets =
                provider.extract_verify_archive(buffer, &options)?;

            // The GUI should check the identity does not already exist
            // but we will double check here to be safe
            let keys = Self::list_accounts()?;
            let existing_key =
                keys.iter().find(|k| k.address == restore_targets.address);
            if existing_key.is_some() {
                return Err(Error::ArchiveAccountAlreadyExists(
                    restore_targets.address,
                ));
            }

            // Write out the identity vault
            let identity_vault_file =
                Self::identity_vault(&restore_targets.address)?;
            std::fs::write(identity_vault_file, &restore_targets.identity.1)?;

            // Check if the identity name already exists
            // and rename the identity being imported if necessary
            let existing_name = keys
                .iter()
                .find(|k| k.label == restore_targets.identity.0.name());
            let label = if existing_name.is_some() {
                let name = format!(
                    "{} ({})",
                    restore_targets.identity.0.name(),
                    &restore_targets.address
                );
                AccountManager::rename_identity(
                    &restore_targets.address,
                    name.clone(),
                )?;
                name
            } else {
                restore_targets.identity.0.name().to_owned()
            };

            // Prepare the vaults directory
            let vaults_dir =
                Self::local_vaults_dir(&restore_targets.address)?;
            std::fs::create_dir_all(&vaults_dir)?;

            // Write out each vault and the WAL log
            for (buffer, vault) in restore_targets.vaults {
                let mut vault_path = vaults_dir.join(vault.id().to_string());
                let mut wal_path = vault_path.clone();
                vault_path.set_extension(VAULT_EXT);
                wal_path.set_extension(WAL_EXT);

                // Write out the vault buffer
                std::fs::write(&vault_path, &buffer)?;

                // Write out the WAL file
                let mut wal_events = Vec::new();
                let create_vault = WalEvent::CreateVault(Cow::Owned(buffer));
                wal_events.push(create_vault);
                let mut wal = WalFile::new(wal_path)?;
                wal.apply(wal_events, None)?;
            }

            AccountInfo {
                address: restore_targets.address,
                label,
            }
        };

        Ok(account)
    }
}
