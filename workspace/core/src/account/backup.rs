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

use uuid::Uuid;
use walkdir::WalkDir;

use crate::{
    account::{
        archive::{ArchiveItem, Inventory, Reader, Writer},
        AccountInfo, DelegatedPassphrase, Identity, LocalAccounts,
    },
    constants::{VAULT_EXT, WAL_EXT},
    decode, encode,
    events::WalEvent,
    passwd::ChangePassword,
    search::SearchIndex,
    sha2::{Digest, Sha256},
    storage::StorageDirs,
    vault::{
        secret::SecretId, Gatekeeper, Summary, Vault, VaultAccess,
        VaultFileAccess, VaultId,
    },
    wal::{file::WalFile, WalProvider},
    Error, Result,
};

use secrecy::SecretString;

/// Get the path to the file storage directory for the given 
/// account address.
type ExtractFilesBuilder = Box<dyn Fn(&str) -> Option<PathBuf>>;

/// Known path or builder for a files directory.
pub enum ExtractFilesLocation {
    /// Known path.
    Path(PathBuf),
    /// Builder for the files directory.
    Builder(ExtractFilesBuilder),
}

/// Options for a restore operation.
pub struct RestoreOptions {
    /// Vaults that the user selected to be imported.
    pub selected: Vec<Summary>,
    /// Passphrase for the identity vault in the archive to copy
    /// the passphrases for imported folders.
    pub passphrase: Option<SecretString>,
    /// Target directory for files.
    pub files_dir: Option<ExtractFilesLocation>,
}

/// Buffers of data to restore after selected options
/// have been applied to the data in an archive.
pub struct RestoreTargets {
    /// The address for the identity.
    pub address: String,
    /// Archive item for the identity vault.
    pub identity: ArchiveItem,
    /// List of vaults to restore.
    pub vaults: Vec<(Vec<u8>, Vault)>,
}

/// Options to use when building an account manifest.
pub struct AccountManifestOptions {
    /// Ignore vaults with the NO_SYNC_SELF flag (default: `true`).
    pub no_sync_self: bool,
}

impl Default for AccountManifestOptions {
    fn default() -> Self {
        Self { no_sync_self: true }
    }
}

/// Manifest of all the data in an account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountManifest {
    /// Identifier for this manifest.
    pub id: Uuid,
    /// Account address.
    pub address: String,
    /// Manifest entries.
    pub entries: Vec<ManifestEntry>,
}

impl AccountManifest {
    /// Create a new account manifest.
    pub fn new(address: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            address,
            entries: Vec::new(),
        }
    }
}

/// Account manifest entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ManifestEntry {
    /// Identity vault.
    Identity {
        /// Identifier for this entry.
        id: Uuid,
        /// Label for the entry.
        label: String,
        /// Size of the file in bytes.
        size: u64,
        /// Checksum of the file data (SHA256).
        checksum: [u8; 32],
    },
    /// Folder vault.
    Vault {
        /// Identifier for this entry.
        id: Uuid,
        /// Label for the entry.
        label: String,
        /// Size of the file in bytes.
        size: u64,
        /// Checksum of the file data (SHA256).
        checksum: [u8; 32],
    },
    /// External file storage.
    File {
        /// Identifier for this entry.
        id: Uuid,
        /// Label for the entry.
        label: String,
        /// Size of the file in bytes.
        size: u64,
        /// Checksum of the file data (SHA256).
        checksum: [u8; 32],
        /// Vault identifier.
        vault_id: VaultId,
        /// Secret identifier.
        secret_id: SecretId,
    },
}

impl ManifestEntry {
    /// Get the identifier for this entry.
    pub fn id(&self) -> &Uuid {
        match self {
            Self::Identity { id, .. } => id,
            Self::Vault { id, .. } => id,
            Self::File { id, .. } => id,
        }
    }

    /// Get the checksum for this entry.
    pub fn checksum(&self) -> [u8; 32] {
        match self {
            Self::Identity { checksum, .. } => *checksum,
            Self::Vault { checksum, .. } => *checksum,
            Self::File { checksum, .. } => *checksum,
        }
    }

    /// Get the label for this entry.
    pub fn label(&self) -> &str {
        match self {
            Self::Identity { label, .. } => label,
            Self::Vault { label, .. } => label,
            Self::File { label, .. } => label,
        }
    }
}

/// Create and restore backup archives.
#[derive(Default)]
pub struct AccountBackup;

impl AccountBackup {
    /// Build a manifest for an account.
    pub fn manifest(
        address: &str,
        options: AccountManifestOptions,
    ) -> Result<(AccountManifest, u64)> {
        let mut total_size: u64 = 0;
        let mut manifest = AccountManifest::new(address.to_owned());
        let path = StorageDirs::identity_vault(address)?;
        let (size, checksum) = Self::read_file_entry(path, None)?;
        let entry = ManifestEntry::Identity {
            id: Uuid::new_v4(),
            label: address.to_owned(),
            size,
            checksum: checksum.as_slice().try_into()?,
        };
        manifest.entries.push(entry);
        total_size += size;

        let vaults = LocalAccounts::list_local_vaults(address, false)?;
        for (summary, path) in vaults {
            if options.no_sync_self && summary.flags().is_no_sync_self() {
                continue;
            }

            let (size, checksum) = Self::read_file_entry(path, None)?;
            let entry = ManifestEntry::Vault {
                id: *summary.id(),
                label: summary.name().to_owned(),
                size,
                checksum: checksum.as_slice().try_into()?,
            };
            manifest.entries.push(entry);
            total_size += size;
        }

        let files = StorageDirs::files_dir(address)?;
        for entry in WalkDir::new(&files) {
            let entry = entry?;
            if entry.path().is_file() {
                let relative = entry.path().strip_prefix(&files)?;

                let mut it = relative.iter();
                if let (Some(vault_id), Some(secret_id), Some(file_name)) =
                    (it.next(), it.next(), it.next())
                {
                    let label = file_name.to_string_lossy().into_owned();
                    let vault_id: VaultId =
                        vault_id.to_string_lossy().parse()?;

                    let secret_id: SecretId =
                        secret_id.to_string_lossy().parse()?;

                    let (size, checksum) = Self::read_file_entry(
                        entry.path(),
                        Some(label.clone()),
                    )?;
                    let entry = ManifestEntry::File {
                        id: Uuid::new_v4(),
                        label,
                        size,
                        checksum: checksum.as_slice().try_into()?,
                        vault_id,
                        secret_id,
                    };
                    manifest.entries.push(entry);
                    total_size += size;
                }
            }
        }
        Ok((manifest, total_size))
    }

    /// Resolve a manifest entry to a path.
    pub fn resolve_manifest_entry(
        address: &str,
        entry: &ManifestEntry,
    ) -> Result<PathBuf> {
        match entry {
            ManifestEntry::Identity { .. } => {
                Ok(StorageDirs::identity_vault(address)?)
            }
            ManifestEntry::Vault { id, .. } => {
                let mut path = StorageDirs::local_vaults_dir(address)?
                    .join(id.to_string());
                path.set_extension(VAULT_EXT);
                Ok(path)
            }
            ManifestEntry::File {
                vault_id,
                secret_id,
                label,
                ..
            } => Ok(StorageDirs::files_dir(address)?
                .join(vault_id.to_string())
                .join(secret_id.to_string())
                .join(label)),
        }
    }

    fn read_file_entry<P: AsRef<Path>>(
        path: P,
        file_name: Option<String>,
    ) -> Result<(u64, [u8; 32])> {
        let mut file = File::open(path)?;
        let size = file.metadata()?.len();
        // For files we already have the checksum encoded in the
        // file name so parse it from the file name
        let checksum = if let Some(file_name) = file_name {
            hex::decode(file_name.as_bytes())?
        // Otherwise for vaults read in the file data and compute
        } else {
            let mut hasher = Sha256::new();
            std::io::copy(&mut file, &mut hasher)?;
            hasher.finalize().to_vec()
        };
        Ok((size, checksum.as_slice().try_into()?))
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
            DelegatedPassphrase::find_vault_passphrase(identity, vault_id)?;

        // Find the local vault for the account
        let (vault, _) =
            LocalAccounts::find_local_vault(address, vault_id, false)?;

        // Change the password before exporting
        let (_, vault, _) = ChangePassword::new(
            &vault,
            current_passphrase,
            new_passphrase,
            None,
        )
        .build()?;

        encode(&vault)
    }

    /// Create a buffer for a zip archive including the
    /// identity vault and all user vaults.
    pub fn export_archive_buffer(address: &str) -> Result<Vec<u8>> {
        let identity_path = StorageDirs::identity_vault(address)?;
        if !identity_path.exists() {
            return Err(Error::NotFile(identity_path));
        }
        let identity = std::fs::read(identity_path)?;

        let vaults = LocalAccounts::list_local_vaults(address, false)?;

        let mut archive = Vec::new();
        let writer = Writer::new(Cursor::new(&mut archive));
        let mut writer =
            writer.set_identity(address.to_owned(), &identity)?;

        for (summary, path) in vaults {
            let buffer = std::fs::read(path)?;
            writer = writer.add_vault(*summary.id(), &buffer)?;
        }

        let files = StorageDirs::files_dir(address)?;
        for entry in WalkDir::new(&files) {
            let entry = entry?;
            if entry.path().is_file() {
                let relative = PathBuf::from("files")
                    .join(entry.path().strip_prefix(&files)?);
                let relative = relative.to_string_lossy().into_owned();
                let buffer = std::fs::read(entry.path())?;
                writer = writer.add_file(&relative, &buffer)?;
            }
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
    pub fn restore_archive_inventory<B: AsRef<[u8]>>(
        mut archive: B,
    ) -> Result<Inventory> {
        let mut reader = Reader::new(Cursor::new(&mut archive))?;
        reader.inventory()
    }

    /// Import from an archive.
    pub fn restore_archive_buffer(
        buffer: Vec<u8>,
        options: RestoreOptions,
        existing_account: bool,
    ) -> Result<(RestoreTargets, AccountInfo)> {
        // FIXME: ensure we still have ONE vault marked as default vault!!!

        // Signed in so use the existing provider
        let (targets, account) = if existing_account {
            let targets = Self::extract_verify_archive(buffer, &options)?;

            let RestoreTargets {
                address,
                identity,
                vaults,
            } = &targets;

            // The GUI should check the identity already exists
            // but we will double check here to be safe
            let keys = LocalAccounts::list_accounts()?;
            let existing_key = keys.iter().find(|k| &k.address == address);
            let account = existing_key
                .ok_or_else(|| Error::NoArchiveAccount(address.to_owned()))?
                .clone();

            if let Some(passphrase) = &options.passphrase {
                let identity_vault_file =
                    StorageDirs::identity_vault(address)?;
                let identity_buffer = std::fs::read(&identity_vault_file)?;
                let identity_vault: Vault = decode(&identity_buffer)?;
                let mut identity_keeper =
                    Gatekeeper::new(identity_vault, None);
                identity_keeper.unlock(passphrase.clone())?;

                let search_index =
                    Arc::new(RwLock::new(SearchIndex::new(None)));
                let restored_identity: Vault = decode(&identity.1)?;
                let mut restored_identity_keeper = Gatekeeper::new(
                    restored_identity,
                    Some(Arc::clone(&search_index)),
                );
                restored_identity_keeper.unlock(passphrase.clone())?;
                restored_identity_keeper.create_search_index()?;

                for (_, vault) in vaults {
                    let vault_passphrase =
                        DelegatedPassphrase::find_vault_passphrase(
                            &restored_identity_keeper,
                            vault.id(),
                        )?;

                    DelegatedPassphrase::save_vault_passphrase(
                        &mut identity_keeper,
                        vault.id(),
                        vault_passphrase,
                    )?;
                }

                // Must re-write the identity vault
                let buffer = encode(identity_keeper.vault())?;
                std::fs::write(identity_vault_file, buffer)?;
            }

            (targets, account)
        // No provider available so the user is not signed in
        } else {
            let restore_targets =
                Self::extract_verify_archive(buffer, &options)?;

            // The GUI should check the identity does not already exist
            // but we will double check here to be safe
            let keys = LocalAccounts::list_accounts()?;
            let existing_key =
                keys.iter().find(|k| k.address == restore_targets.address);
            if existing_key.is_some() {
                return Err(Error::ArchiveAccountAlreadyExists(
                    restore_targets.address,
                ));
            }

            // Write out the identity vault
            let identity_vault_file =
                StorageDirs::identity_vault(&restore_targets.address)?;
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

                let identity_vault_file =
                    StorageDirs::identity_vault(&restore_targets.address)?;
                let mut access = VaultFileAccess::new(identity_vault_file)?;
                access.set_vault_name(name.clone())?;

                name
            } else {
                restore_targets.identity.0.name().to_owned()
            };

            // Prepare the vaults directory
            let vaults_dir =
                StorageDirs::local_vaults_dir(&restore_targets.address)?;
            std::fs::create_dir_all(&vaults_dir)?;

            // Write out each vault and the WAL log
            for (buffer, vault) in &restore_targets.vaults {
                let mut vault_path = vaults_dir.join(vault.id().to_string());
                let mut wal_path = vault_path.clone();
                vault_path.set_extension(VAULT_EXT);
                wal_path.set_extension(WAL_EXT);

                // Write out the vault buffer
                std::fs::write(&vault_path, buffer)?;

                // Write out the WAL file
                let mut wal_events = Vec::new();
                let create_vault =
                    WalEvent::CreateVault(Cow::Borrowed(buffer));
                wal_events.push(create_vault);
                let mut wal = WalFile::new(wal_path)?;
                wal.apply(wal_events, None)?;
            }

            let account = AccountInfo {
                address: restore_targets.address.clone(),
                label,
            };

            (restore_targets, account)
        };

        Ok((targets, account))
    }

    /// Helper to extract from an archive and verify the archive
    /// contents against the restore options.
    pub fn extract_verify_archive(
        mut archive: Vec<u8>,
        options: &RestoreOptions,
    ) -> Result<RestoreTargets> {
        let mut reader = Reader::new(Cursor::new(&mut archive))?.prepare()?;

        if let Some(files_dir) = &options.files_dir {
            match files_dir {
                ExtractFilesLocation::Path(files_dir) => {
                    reader.extract_files(files_dir, options.selected.as_slice())?;
                }
                ExtractFilesLocation::Builder(builder) => {
                    if let Some(manifest) = reader.manifest() {
                        if let Some(files_dir) = builder(&manifest.address) {
                            reader
                                .extract_files(files_dir, options.selected.as_slice())?;
                        }
                    }
                }
            }
        }
        
        /*
        if let Some(files_dir) = &options.files_dir {
            reader.extract_files(files_dir, options.selected.as_slice())?;
        } else if let (Some(builder), Some(manifest)) =
            (&options.files_dir_builder, reader.manifest())
        {
            if let Some(files_dir) = builder(&manifest.address) {
                reader
                    .extract_files(files_dir, options.selected.as_slice())?;
            }
        }
        */

        let (address, identity, vaults) = reader.finish()?;

        // Filter extracted vaults to those selected by the user
        let vaults = vaults
            .into_iter()
            .filter(|item| {
                options.selected.iter().any(|s| s.id() == item.0.id())
            })
            .collect::<Vec<_>>();

        // Check each target vault can be decoded
        let mut decoded: Vec<(Vec<u8>, Vault)> = Vec::new();
        for item in vaults {
            let vault: Vault = decode(&item.1)?;
            decoded.push((item.1, vault));
        }

        // Check all the decoded vaults can be decrypted
        if let Some(passphrase) = &options.passphrase {
            // Check the identity vault can be unlocked
            let vault: Vault = decode(&identity.1)?;
            let mut keeper = Gatekeeper::new(vault, None);
            keeper.unlock(passphrase.clone())?;

            // Get the signing address from the identity vault and
            // verify it matches the manifest address
            let user = Identity::login_buffer(
                &identity.1,
                passphrase.clone(),
                None,
                None,
            )?;
            if user.address() != address {
                return Err(Error::ArchiveAddressMismatch);
            }
        }

        Ok(RestoreTargets {
            address,
            identity,
            vaults: decoded,
        })
    }
}
