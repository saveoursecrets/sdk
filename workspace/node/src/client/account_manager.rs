//! Account manager provides utility functions for
//! creating and managing local accounts.
use std::{borrow::Cow, io::Cursor, path::PathBuf};

use sos_core::{
    archive::{deflate, inflate, Inventory, Reader, Writer},
    constants::{IDENTITY_DIR, LOCAL_DIR, VAULTS_DIR, VAULT_EXT, WAL_EXT},
    encode,
    events::WalEvent,
    identity::{AuthenticatedUser, Identity},
    signer::SingleParty,
    vault::{Header, Summary, Vault, VaultAccess},
    wal::{file::WalFile, WalProvider},
    Gatekeeper, VaultFileAccess,
};

use crate::{
    cache_dir,
    client::{
        provider::{BoxedProvider, ProviderFactory, RestoreOptions},
        run_blocking, Error, Result,
    },
};

use secrecy::{ExposeSecret, SecretString};

/// Combines an account address with a label.
#[derive(Debug, Clone)]
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

/// Manage accounts using the file system and a local provider.
#[derive(Default)]
pub struct AccountManager {}

impl AccountManager {
    /// Create a new account.
    pub fn new_account(
        account_name: String,
        passphrase: SecretString,
    ) -> Result<(String, AuthenticatedUser, Summary)> {
        // Prepare the identity vault
        let (address, identity_vault) =
            Identity::new_login_vault(account_name, passphrase.clone())?;

        // Authenticate on the newly created identity vault so we
        // can get the signing key for provider communication
        let buffer = encode(&identity_vault)?;
        let (user, _) = Identity::login_buffer(buffer, passphrase.clone())?;

        // Persist the identity vault to disc
        let identity_vault_file = Self::identity_vault(&address)?;
        let buffer = encode(&identity_vault)?;
        std::fs::write(identity_vault_file, buffer)?;

        // Create local provider
        let factory = ProviderFactory::Local;
        let (mut provider, _) =
            factory.create_provider(user.signer.clone())?;
        run_blocking(provider.authenticate())?;

        // Prepare the default vault
        let mut default_vault: Vault = Default::default();
        default_vault.set_default_flag(true);
        default_vault.initialize(passphrase.expose_secret())?;

        // Save the default vault
        let buffer = encode(&default_vault)?;
        let summary =
            run_blocking(provider.create_account_with_buffer(buffer))?;

        Ok((address, user, summary))
    }

    /// Sign in a user.
    pub fn sign_in(
        address: String,
        passphrase: SecretString,
    ) -> Result<(AccountInfo, AuthenticatedUser, Gatekeeper)> {
        let accounts = Self::list_accounts()?;
        let account = accounts
            .into_iter()
            .find(|a| a.address == address)
            .ok_or_else(|| Error::NoAccount(address.clone()))?;

        let identity_path = Self::identity_vault(&address)?;
        let (user, keeper) = Identity::login_file(identity_path, passphrase)?;

        Ok((account, user, keeper))
    }

    /// Verify the master passphrase for an account.
    pub fn verify(address: &str, passphrase: SecretString) -> Result<bool> {
        let identity_path = Self::identity_vault(&address)?;
        let result = Identity::login_file(identity_path, passphrase);
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

        let local_dir = cache_dir().ok_or(Error::NoCache)?.join(LOCAL_DIR);
        let identity_data_dir = local_dir.join(address);

        std::fs::remove_file(&identity_vault_file)?;
        std::fs::remove_dir_all(&identity_data_dir)?;

        Ok(())
    }

    /// Get a list of the vaults for an account directly from the file system.
    pub fn list_local_vaults(
        address: &str,
    ) -> Result<Vec<(Summary, PathBuf)>> {
        let local_dir = cache_dir().ok_or(Error::NoCache)?.join(LOCAL_DIR);
        let vaults_dir = local_dir.join(address).join(VAULTS_DIR);
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
        let writer = Writer::new(&mut archive);
        let mut writer =
            writer.set_identity(address.to_owned(), &identity)?;

        for (summary, path) in vaults {
            let buffer = std::fs::read(path)?;
            writer = writer.add_vault(*summary.id(), &buffer)?;
        }

        writer.finish()?;

        let mut compressed = Vec::new();
        deflate(archive.as_slice(), &mut compressed)?;
        Ok(compressed)
    }

    /// Read the inventory from an archive.
    pub fn restore_archive_inventory(buffer: Vec<u8>) -> Result<Inventory> {
        let mut archive = Vec::new();
        inflate(buffer.as_slice(), &mut archive)?;

        let reader = Reader::new(Cursor::new(archive));
        let inventory = reader.inventory()?;
        //let mut inventory: Inventory = inventory.into();
        //
        /*
        let accounts = Self::list_accounts()?;
        inventory.exists_local =
            accounts.iter().any(|account| account.address == inventory.manifest.address);
        */
        Ok(inventory)
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
        let overwrite_identity = options.overwrite_identity;

        // FIXME: ensure we still have ONE vault marked as default vault!!!

        // Signed in so use the existing provider
        let account = if let Some(provider) = provider {
            let (address, identity) =
                run_blocking(provider.restore_archive(buffer, options))?;

            // The GUI should check the identity does not already exist
            // but we will double check here to be safe
            let keys = Self::list_accounts()?;
            let existing_key = keys.iter().find(|k| k.address == address);
            let account = existing_key
                .ok_or_else(|| Error::NoArchiveAccount(address.to_owned()))?
                .clone();

            if overwrite_identity {
                let identity_vault_file = Self::identity_vault(&address)?;
                std::fs::write(identity_vault_file, identity.1)?;
            }

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
            let cache_dir = cache_dir().ok_or(Error::NoCache)?;
            let vaults_dir = cache_dir
                .join(LOCAL_DIR)
                .join(&restore_targets.address)
                .join(VAULTS_DIR);
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
