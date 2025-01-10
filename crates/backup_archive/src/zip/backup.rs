//! Account archive backup.
use super::{Error, Result};
use crate::zip::{Inventory, Reader, Writer};
use crate::RestoreTargets;
use hex;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sos_backend::reducers::FolderReducer;
use sos_core::{
    constants::VAULT_EXT, crypto::AccessKey, decode, events::EventLog,
    SecretId, VaultId,
};
use sos_core::{AccountId, Paths};
use sos_filesystem::events::FolderEventLog;
use sos_filesystem::VaultFileWriter;
use sos_login::{DiscIdentityFolder, Identity, PublicIdentity};
use sos_vault::{Summary, Vault, VaultAccess};
use sos_vfs::{self as vfs, File};
use std::{
    io::Cursor,
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use tokio::io::{AsyncBufRead, AsyncSeek, BufReader};
use uuid::Uuid;
use walkdir::WalkDir;

/// Get the path to the file storage directory for the given
/// account address.
type ExtractFilesBuilder = Box<dyn Fn(&str) -> Option<PathBuf> + Send + Sync>;

/// Known path or builder for a files directory.
///
/// When extracting an archive to restore an account a user
/// maybe authenticated. If the user is authenticated the file
/// extraction directory can be determined ahead of time, but
/// if we don't have an authenticated user then the files directory
/// should be determined by the address extracted from the archive
/// manifest.
pub enum ExtractFilesLocation {
    /// Known path for the files directory.
    Path(PathBuf),
    /// Builder for the files directory.
    Builder(ExtractFilesBuilder),
}

/// Options for a restore operation.
#[derive(Default)]
pub struct RestoreOptions {
    /// Vaults that the user selected to be imported.
    pub selected: Vec<Summary>,
    /// Target directory for files.
    pub files_dir: Option<ExtractFilesLocation>,
}

/// Options to use when building an account manifest.
pub struct AccountManifestOptions {
    /// Ignore vaults with the NO_SYNC flag (default: `true`).
    pub no_sync: bool,
}

impl Default for AccountManifestOptions {
    fn default() -> Self {
        Self { no_sync: true }
    }
}

/// Manifest of all the data in an account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountManifest {
    /// Identifier for this manifest.
    pub id: Uuid,
    /// Account address.
    pub address: AccountId,
    /// Manifest entries.
    pub entries: Vec<ManifestEntry>,
}

impl AccountManifest {
    /// Create a new account manifest.
    pub fn new(address: AccountId) -> Self {
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
    pub async fn manifest(
        address: &AccountId,
        paths: &Paths,
        options: AccountManifestOptions,
    ) -> Result<(AccountManifest, u64)> {
        let mut total_size: u64 = 0;
        let mut manifest = AccountManifest::new(*address);
        let path = paths.identity_vault();
        let (size, checksum) = Self::read_file_entry(path, None).await?;
        let entry = ManifestEntry::Identity {
            id: Uuid::new_v4(),
            label: address.to_string(),
            size,
            checksum: checksum.as_slice().try_into()?,
        };
        manifest.entries.push(entry);
        total_size += size;

        let vaults = Identity::list_local_folders(paths).await?;
        for (summary, path) in vaults {
            if options.no_sync && summary.flags().is_sync_disabled() {
                continue;
            }

            let (size, checksum) = Self::read_file_entry(path, None).await?;
            let entry = ManifestEntry::Vault {
                id: *summary.id(),
                label: summary.name().to_owned(),
                size,
                checksum: checksum.as_slice().try_into()?,
            };
            manifest.entries.push(entry);
            total_size += size;
        }

        let files = paths.files_dir();
        for entry in WalkDir::new(files) {
            let entry = entry?;
            if vfs::metadata(entry.path()).await?.is_file() {
                let relative = entry.path().strip_prefix(files)?;

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
                    )
                    .await?;
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
        _address: &AccountId,
        paths: &Paths,
        entry: &ManifestEntry,
    ) -> Result<PathBuf> {
        match entry {
            ManifestEntry::Identity { .. } => Ok(paths.identity_vault()),
            ManifestEntry::Vault { id, .. } => {
                let mut path = paths.vaults_dir().join(id.to_string());
                path.set_extension(VAULT_EXT);
                Ok(path)
            }
            ManifestEntry::File {
                vault_id,
                secret_id,
                label,
                ..
            } => Ok(paths
                .files_dir()
                .join(vault_id.to_string())
                .join(secret_id.to_string())
                .join(label)),
        }
    }

    async fn read_file_entry<P: AsRef<Path>>(
        path: P,
        file_name: Option<String>,
    ) -> Result<(u64, [u8; 32])> {
        let file = File::open(path.as_ref()).await?;
        let size = file.metadata().await?.len();
        // For files we already have the checksum encoded in the
        // file name so parse it from the file name
        let checksum = if let Some(file_name) = file_name {
            hex::decode(file_name.as_bytes())?
        // Otherwise for vaults read in the file data and compute
        } else {
            let buffer = vfs::read(path.as_ref()).await?;
            let mut hasher = Sha256::new();
            hasher.update(&buffer);
            hasher.finalize().to_vec()
        };
        Ok((size, checksum.as_slice().try_into()?))
    }

    /// Create a buffer for a zip archive including the
    /// identity vault and all user vaults.
    pub async fn export_archive_buffer(
        address: &AccountId,
        paths: &Paths,
    ) -> Result<Vec<u8>> {
        let identity_path = paths.identity_vault();
        if !vfs::try_exists(&identity_path).await? {
            return Err(Error::NotFile(identity_path));
        }
        let identity = vfs::read(identity_path).await?;

        let vaults = Identity::list_local_folders(paths).await?;

        let mut archive = Vec::new();
        let writer = Writer::new(Cursor::new(&mut archive));
        let mut writer = writer.set_identity(address, &identity).await?;

        for (summary, path) in vaults {
            let buffer = vfs::read(path).await?;
            writer = writer.add_vault(*summary.id(), &buffer).await?;
        }

        let device_info = if vfs::try_exists(paths.device_file()).await?
            && vfs::try_exists(paths.device_events()).await?
        {
            let vault_buffer = vfs::read(paths.device_file()).await?;
            let events_buffer = vfs::read(paths.device_events()).await?;
            Some((vault_buffer, events_buffer))
        } else {
            None
        };

        if let Some((vault, events)) = device_info {
            writer = writer
                .add_devices(vault.as_slice(), events.as_slice())
                .await?;
        }

        if vfs::try_exists(paths.account_events()).await? {
            let buffer = vfs::read(paths.account_events()).await?;
            writer = writer.add_account_events(buffer.as_slice()).await?;
        }

        if vfs::try_exists(paths.file_events()).await? {
            let buffer = vfs::read(paths.file_events()).await?;
            writer = writer.add_file_events(buffer.as_slice()).await?;
        }

        if vfs::try_exists(paths.preferences_file()).await? {
            let buffer = vfs::read(paths.preferences_file()).await?;
            writer = writer.add_preferences(buffer.as_slice()).await?;
        }

        if vfs::try_exists(paths.remote_origins()).await? {
            let buffer = vfs::read(paths.remote_origins()).await?;
            writer = writer.add_remote_servers(buffer.as_slice()).await?;
        }

        // TODO: use list_external_files() rather than
        // TODO: walking the directory
        let files = paths.files_dir();
        for entry in WalkDir::new(files) {
            let entry = entry?;
            if vfs::metadata(entry.path()).await?.is_file() {
                let relative = PathBuf::from("files")
                    .join(entry.path().strip_prefix(files)?);
                let relative = relative.to_string_lossy().into_owned();
                let buffer = vfs::read(entry.path()).await?;
                writer = writer.add_file(&relative, &buffer).await?;
            }
        }

        writer.finish().await?;
        Ok(archive)
    }

    /// Export an archive of the account to disc.
    pub async fn export_archive_file<P: AsRef<Path>>(
        path: P,
        address: &AccountId,
        paths: &Paths,
    ) -> Result<()> {
        let buffer = Self::export_archive_buffer(address, paths).await?;
        vfs::write(path.as_ref(), buffer).await?;
        Ok(())
    }

    /// Read the inventory from an archive.
    pub async fn restore_archive_inventory<
        R: AsyncBufRead + AsyncSeek + Unpin,
    >(
        archive: R,
    ) -> Result<Inventory> {
        let mut reader = Reader::new(archive).await?;
        Ok(reader.inventory().await?)
    }

    /// Import from an archive.
    ///
    /// The owner must not be signed in and the account must not exist.
    pub async fn import_archive_file(
        path: impl AsRef<Path>,
        options: RestoreOptions,
        data_dir: Option<PathBuf>,
    ) -> Result<(RestoreTargets, PublicIdentity)> {
        let file = vfs::File::open(path).await?;
        Self::import_archive_reader(BufReader::new(file), options, data_dir)
            .await
    }

    /// Import from an archive.
    ///
    /// The owner must not be signed in and the account must not exist.
    pub async fn import_archive_reader<
        R: AsyncBufRead + AsyncSeek + Unpin,
    >(
        buffer: R,
        options: RestoreOptions,
        mut data_dir: Option<PathBuf>,
    ) -> Result<(RestoreTargets, PublicIdentity)> {
        // FIXME: ensure we still have ONE vault marked as default vault!!!
        //

        let data_dir = if let Some(data_dir) = data_dir.take() {
            data_dir
        } else {
            Paths::data_dir()?
        };

        let restore_targets =
            Self::extract_verify_archive(buffer, &options, None).await?;

        // The app should check the identity does not already exist
        // but we will double check here to be safe
        let paths = Paths::new_global(data_dir.clone());
        let keys = Identity::list_accounts(Some(&paths)).await?;
        let existing_account = keys
            .iter()
            .find(|k| k.account_id() == &restore_targets.manifest.account_id);

        if existing_account.is_some() {
            return Err(Error::ArchiveAccountAlreadyExists(
                restore_targets.manifest.account_id.to_string(),
            ));
        }

        let address_path = restore_targets.manifest.account_id.to_string();
        let paths = Paths::new(data_dir, &address_path);

        // Write out the identity vault
        let identity_vault_file = paths.identity_vault();
        vfs::write(identity_vault_file, &restore_targets.identity.1).await?;

        // Check if the identity name already exists
        // and rename the identity being imported if necessary
        let existing_name = keys
            .iter()
            .find(|k| k.label() == restore_targets.identity.0.name());

        let label = if existing_name.is_some() {
            let name = format!(
                "{} ({})",
                restore_targets.identity.0.name(),
                &restore_targets.manifest.account_id
            );

            let identity_vault_file = paths.identity_vault();

            let mut access =
                VaultFileWriter::<Error>::new(identity_vault_file).await?;
            access.set_vault_name(name.clone()).await?;

            name
        } else {
            restore_targets.identity.0.name().to_owned()
        };

        // Prepare the vaults directory
        let vaults_dir = paths.vaults_dir();
        vfs::create_dir_all(&vaults_dir).await?;

        Self::restore_system(&paths, &restore_targets).await?;
        Self::restore_user_folders(&paths, &restore_targets.vaults).await?;

        let account =
            PublicIdentity::new(label, restore_targets.manifest.account_id);
        Ok((restore_targets, account))
    }

    async fn restore_user_folders(
        paths: &Paths,
        vaults: &Vec<(Vec<u8>, Vault)>,
    ) -> Result<()> {
        // Write out each vault and the event log
        for (buffer, vault) in vaults {
            let vault_path = paths.vault_path(vault.id());
            let event_log_path = paths.event_log_path(vault.id());

            // Write out the vault buffer
            vfs::write_exclusive(&vault_path, buffer).await?;

            let (_, events) =
                FolderReducer::split::<Error>(vault.clone()).await?;

            // Write out the event log file
            let mut event_log =
                FolderEventLog::<Error>::new(event_log_path).await?;
            event_log.apply(events.iter().collect()).await?;
        }

        Ok(())
    }

    /// Restore system files from the restore targets.
    async fn restore_system(
        paths: &Paths,
        targets: &RestoreTargets,
    ) -> Result<()> {
        let RestoreTargets {
            devices,
            account: account_events,
            files,
            preferences,
            remotes,
            ..
        } = targets;

        // Restore account events
        if let Some(buffer) = account_events {
            vfs::write_exclusive(paths.account_events(), buffer).await?;
        }

        // Restore device events and vault
        if let Some((vault, events)) = devices {
            vfs::write_exclusive(paths.device_file(), vault).await?;
            vfs::write_exclusive(paths.device_events(), events).await?;
        }

        // Restore file events
        if let Some(buffer) = files {
            vfs::write_exclusive(paths.file_events(), buffer).await?;
        }

        // Restore account preferences
        if let Some(buffer) = preferences {
            vfs::write_exclusive(paths.preferences_file(), buffer).await?;
        }

        // Restore remote server origins
        if let Some(buffer) = remotes {
            vfs::write_exclusive(paths.remote_origins(), buffer).await?;
        }

        Ok(())
    }

    /// Restore from an archive.
    ///
    /// The account owner must be signed in and supply the password
    /// for the archive identity vault.
    pub async fn restore_archive_reader<
        R: AsyncBufRead + AsyncSeek + Unpin,
    >(
        reader: R,
        options: RestoreOptions,
        passphrase: SecretString,
        mut data_dir: Option<PathBuf>,
    ) -> Result<(RestoreTargets, PublicIdentity)> {
        // FIXME: ensure we still have ONE vault marked as default vault!!!

        let data_dir = if let Some(data_dir) = data_dir.take() {
            data_dir
        } else {
            Paths::data_dir()?
        };

        let targets = Self::extract_verify_archive(
            reader,
            &options,
            Some(passphrase.clone()),
        )
        .await?;

        let RestoreTargets {
            manifest,
            identity,
            vaults,
            ..
        } = &targets;

        // The app should check the identity already exists
        // but we will double check here to be safe
        let paths = Paths::new_global(data_dir.clone());
        let keys = Identity::list_accounts(Some(&paths)).await?;
        let existing_account =
            keys.iter().find(|k| k.account_id() == &manifest.account_id);

        let account = existing_account
            .ok_or_else(|| {
                Error::NoArchiveAccount(manifest.account_id.to_string())
            })?
            .clone();

        let account_id = manifest.account_id.to_string();
        let paths = Paths::new(data_dir, &account_id);
        let mut user = Identity::new(paths.clone());
        let key: AccessKey = passphrase.clone().into();
        let identity_vault_file = paths.identity_vault().clone();
        user.login(&manifest.account_id, &identity_vault_file, &key)
            .await?;

        let restored_user =
            try_restore_user(&manifest.account_id, &identity.1, &key).await?;

        // Prepare the vaults directory
        let vaults_dir = paths.vaults_dir();
        vfs::create_dir_all(&vaults_dir).await?;

        // Use the delegated passwords for the folders
        // that were restored
        for (_, vault) in vaults {
            let vault_passphrase = restored_user
                .find_folder_password(vault.id())
                .await?
                .ok_or(Error::NoFolderPassword(*vault.id()))?;

            user.save_folder_password(vault.id(), vault_passphrase)
                .await?;
        }

        Self::restore_system(&paths, &targets).await?;
        Self::restore_user_folders(&paths, &targets.vaults).await?;

        Ok((targets, account))
    }

    /// Helper to extract from an archive and verify the archive
    /// contents against the restore options.
    async fn extract_verify_archive<R: AsyncBufRead + AsyncSeek + Unpin>(
        archive: R,
        options: &RestoreOptions,
        password: Option<SecretString>,
    ) -> Result<RestoreTargets> {
        let mut reader = Reader::new(archive).await?.prepare().await?;

        if let Some(files_dir) = &options.files_dir {
            match files_dir {
                ExtractFilesLocation::Path(files_dir) => {
                    reader
                        .extract_files(files_dir, options.selected.as_slice())
                        .await?;
                }
                ExtractFilesLocation::Builder(builder) => {
                    if let Some(manifest) = reader.manifest() {
                        let account_id = manifest.account_id.to_string();
                        if let Some(files_dir) = builder(&account_id) {
                            reader
                                .extract_files(
                                    files_dir,
                                    options.selected.as_slice(),
                                )
                                .await?;
                        }
                    }
                }
            }
        }

        let (
            manifest,
            identity,
            vaults,
            devices,
            account,
            files,
            preferences,
            remotes,
        ) = reader.finish().await?;

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
            let vault: Vault = decode(&item.1).await?;
            decoded.push((item.1, vault));
        }

        // Check all the decoded vaults can be decrypted
        if let Some(passphrase) = &password {
            // Check the identity vault can be unlocked
            // and get the signing address from the identity folder
            // and verify it matches the manifest address
            let key: AccessKey = passphrase.clone().into();
            let restored_user =
                try_restore_user(&manifest.account_id, &identity.1, &key)
                    .await?;

            let account_id = restored_user.account_id();
            if account_id != &manifest.account_id {
                return Err(Error::ArchiveAccountIdMismatch);
            }
        }

        let devices = if let Some((vault_item, event_item)) = devices {
            Some((vault_item.1, event_item))
        } else {
            None
        };

        Ok(RestoreTargets {
            manifest,
            identity,
            vaults: decoded,
            account,
            devices,
            files,
            preferences,
            remotes,
        })
    }
}

/// Try to authenticate an identity folder using a
/// vault written to a temp file.
async fn try_restore_user(
    account_id: &AccountId,
    vault: &[u8],
    access_key: &AccessKey,
) -> Result<DiscIdentityFolder> {
    let file = NamedTempFile::new()?;
    vfs::write(file.path(), vault).await?;
    let restored_user =
        DiscIdentityFolder::login(account_id, file.path(), access_key)
            .await?;
    Ok(restored_user)
}
