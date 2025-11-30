//! Account archive backup.
use crate::archive::{
    ArchiveItem, Error, ManifestVersion1, RestoreTargets, Result,
};
use crate::{write_exclusive, FolderEventLog, VaultFileWriter};
use hex;
use sha2::{Digest, Sha256};
use sos_archive::{sanitize_file_path, ZipReader};
use sos_core::events::EventLogType;
use sos_core::AccountId;
use sos_core::{
    constants::{
        ACCOUNT_EVENTS, DEVICE_FILE, EVENT_LOG_EXT, FILES_DIR, FILE_EVENTS,
        JSON_EXT, PREFERENCES_FILE, REMOTES_FILE, VAULT_EXT,
    },
    decode,
    events::EventLog,
    Paths, PublicIdentity, VaultId,
};
use sos_reducers::FolderReducer;
use sos_vault::{list_accounts, EncryptedEntry, Header, Vault};
use sos_vfs::{self as vfs, File};
use std::path::{Path, PathBuf};
use tokio::io::BufReader;
use tokio_util::compat::TokioAsyncWriteCompatExt;

/// Import from an archive.
///
/// The owner must not be signed in and the account must not exist.
pub async fn import_backup_archive(
    path: impl AsRef<Path>,
    paths: &Paths,
) -> Result<PublicIdentity> {
    let file = vfs::File::open(path).await?;
    import_archive_reader(BufReader::new(file), paths).await
}

/// Import from an archive.
///
/// The owner must not be signed in and the account must not exist.
async fn import_archive_reader(
    buffer: BufReader<File>,
    paths: &Paths,
) -> Result<PublicIdentity> {
    let restore_targets = extract_archive(buffer, paths).await?;

    // The app should check the identity does not already exist
    // but we will double check here to be safe
    let keys = list_accounts(Some(paths)).await?;
    let existing_account = keys
        .iter()
        .find(|k| k.account_id() == &restore_targets.manifest.account_id);

    if existing_account.is_some() {
        return Err(Error::ArchiveAccountAlreadyExists(
            restore_targets.manifest.account_id.to_string(),
        ));
    }

    let account_id = restore_targets.manifest.account_id;
    let paths = paths.with_account_id(&account_id);

    // Write out the identity vault
    let identity_vault: Vault = decode(&restore_targets.identity.1).await?;
    let identity_vault_file = paths.identity_vault();
    vfs::write(identity_vault_file, &restore_targets.identity.1).await?;

    // Write out the identity event log file
    let (_, events) = FolderReducer::split::<Error>(identity_vault).await?;
    let mut event_log = FolderEventLog::<Error>::new_folder(
        paths.identity_events(),
        account_id,
        EventLogType::Identity,
    )
    .await?;
    event_log.apply(events.as_slice()).await?;

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

        let mut access = VaultFileWriter::<Error>::new(identity_vault_file);
        access.set_vault_name(name.clone()).await?;

        name
    } else {
        restore_targets.identity.0.name().to_owned()
    };

    // Prepare the vaults directory
    let vaults_dir = paths.vaults_dir();
    vfs::create_dir_all(&vaults_dir).await?;

    restore_system(&paths, &restore_targets).await?;
    restore_user_folders(&paths, &account_id, &restore_targets.vaults)
        .await?;
    let account =
        PublicIdentity::new(restore_targets.manifest.account_id, label);
    Ok(account)
}

async fn restore_user_folders(
    paths: &Paths,
    account_id: &AccountId,
    vaults: &Vec<(Vec<u8>, Vault)>,
) -> Result<()> {
    // Write out each vault and the event log
    for (buffer, vault) in vaults {
        let folder_id = *vault.id();
        let vault_path = paths.vault_path(&folder_id);
        let event_log_path = paths.event_log_path(&folder_id);

        // Write out the vault buffer
        write_exclusive(&vault_path, buffer).await?;

        let (_, events) =
            FolderReducer::split::<Error>(vault.clone()).await?;

        // Write out the event log file
        let mut event_log = FolderEventLog::<Error>::new_folder(
            event_log_path,
            *account_id,
            EventLogType::Folder(folder_id),
        )
        .await?;
        event_log.apply(events.as_slice()).await?;
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
        write_exclusive(paths.account_events(), buffer).await?;
    }

    // Restore device events and vault
    if let Some((vault, events)) = devices {
        write_exclusive(paths.device_file(), vault).await?;
        write_exclusive(paths.device_events(), events).await?;
    }

    // Restore file events
    if let Some(buffer) = files {
        write_exclusive(paths.file_events(), buffer).await?;
    }

    // Restore account preferences
    if let Some(buffer) = preferences {
        write_exclusive(paths.preferences_file(), buffer).await?;
    }

    // Restore remote server origins
    if let Some(buffer) = remotes {
        write_exclusive(paths.remote_origins(), buffer).await?;
    }

    Ok(())
}

/// Helper to extract from an archive and verify the archive
/// contents against the restore options.
async fn extract_archive(
    archive: BufReader<File>,
    paths: &Paths,
) -> Result<RestoreTargets> {
    let mut reader = ZipReader::new(archive).await?;

    let mut manifest = reader.find_manifest::<ManifestVersion1>().await?;
    let manifest = manifest.take().ok_or(Error::NoArchiveManifest)?;
    let paths = paths.with_account_id(&manifest.account_id);
    extract_files(&mut reader, &paths).await?;
    let (
        manifest,
        identity,
        vaults,
        devices,
        account,
        files,
        preferences,
        remotes,
    ) = finish(reader, manifest).await?;

    // Check each target vault can be decoded
    let mut decoded: Vec<(Vec<u8>, Vault)> = Vec::new();
    for item in vaults {
        let vault: Vault = decode(&item.1).await?;
        decoded.push((item.1, vault));
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

/// Extract files to a destination.
async fn extract_files(
    reader: &mut ZipReader<BufReader<vfs::File>>,
    paths: &Paths,
) -> Result<()> {
    for index in 0..reader.inner().file().entries().len() {
        let entry = reader.inner().file().entries().get(index).unwrap();
        let is_dir = entry.dir().map_err(sos_archive::Error::from)?;

        if !is_dir {
            let file_name = entry.filename();

            let path = sanitize_file_path(
                file_name.as_str().map_err(sos_archive::Error::from)?,
            );
            let mut it = path.iter();
            if let (Some(first), Some(second)) = (it.next(), it.next())
                && first == FILES_DIR
                    && let Ok(_vault_id) =
                        second.to_string_lossy().parse::<VaultId>()
                    {
                        // Only restore files for the selected vaults
                        //
                        // The given target path should already
                        // include any files/ prefix so we need
                        // to skip it
                        let mut relative = PathBuf::new();
                        for part in path.iter().skip(1) {
                            relative = relative.join(part);
                        }
                        let destination = paths.files_dir().join(relative);
                        if let Some(parent) = destination.parent()
                            && !vfs::try_exists(&parent).await? {
                                vfs::create_dir_all(parent).await?;
                            }

                        let mut reader = reader
                            .inner_mut()
                            .reader_without_entry(index)
                            .await
                            .map_err(sos_archive::Error::from)?;
                        let output = File::create(destination).await?;
                        futures_util::io::copy(
                            &mut reader,
                            &mut output.compat_write(),
                        )
                        .await?;
                    }
        }
    }

    Ok(())
}

/// Finish reading by validating entries against the manifest.
///
/// This will verify the buffers match the checksums in
/// the manifest.
///
/// It also extracts the vault summaries so we are confident
/// each buffer is a valid vault.
async fn finish(
    mut reader: ZipReader<BufReader<vfs::File>>,
    manifest: ManifestVersion1,
) -> Result<(
    ManifestVersion1,
    ArchiveItem,
    Vec<ArchiveItem>,
    Option<(ArchiveItem, Vec<u8>)>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
)> {
    let entry_name = format!("{}.{}", manifest.account_id, VAULT_EXT);
    let checksum = hex::decode(&manifest.checksum)?;
    let identity = archive_folder(&mut reader, &entry_name, checksum).await?;
    let mut vaults = Vec::new();

    for (k, v) in &manifest.vaults {
        let entry_name = format!("{}.{}", k, VAULT_EXT);
        let checksum = hex::decode(v)?;
        vaults
            .push(archive_folder(&mut reader, &entry_name, checksum).await?);
    }

    let devices = if let Some((vault_checksum, event_checksum)) =
        &manifest.devices
    {
        let devices_vault_name = format!("{}.{}", DEVICE_FILE, VAULT_EXT);
        let devices_event_name = format!("{}.{}", DEVICE_FILE, EVENT_LOG_EXT);
        let devices_vault = archive_folder(
            &mut reader,
            &devices_vault_name,
            hex::decode(vault_checksum)?,
        )
        .await?;
        let devices_event = archive_buffer(
            &mut reader,
            &devices_event_name,
            hex::decode(event_checksum)?,
        )
        .await?;
        Some((devices_vault, devices_event))
    } else {
        None
    };

    let account = if let Some(checksum) = &manifest.account {
        let name = format!("{}.{}", ACCOUNT_EVENTS, EVENT_LOG_EXT);
        let events =
            archive_buffer(&mut reader, &name, hex::decode(checksum)?)
                .await?;
        Some(events)
    } else {
        None
    };

    let files = if let Some(checksum) = &manifest.files {
        let name = format!("{}.{}", FILE_EVENTS, EVENT_LOG_EXT);
        let events =
            archive_buffer(&mut reader, &name, hex::decode(checksum)?)
                .await?;
        Some(events)
    } else {
        None
    };

    let prefs = if let Some(checksum) = &manifest.preferences {
        let name = format!("{}.{}", PREFERENCES_FILE, JSON_EXT);
        let events =
            archive_buffer(&mut reader, &name, hex::decode(checksum)?)
                .await?;
        Some(events)
    } else {
        None
    };

    let remotes = if let Some(checksum) = &manifest.remotes {
        let name = format!("{}.{}", REMOTES_FILE, JSON_EXT);
        let events =
            archive_buffer(&mut reader, &name, hex::decode(checksum)?)
                .await?;
        Some(events)
    } else {
        None
    };

    Ok((
        manifest, identity, vaults, devices, account, files, prefs, remotes,
    ))
}

async fn archive_folder(
    reader: &mut ZipReader<BufReader<File>>,
    name: &str,
    checksum: Vec<u8>,
) -> Result<ArchiveItem> {
    let data = reader.by_name(name).await?.unwrap();
    let digest = Sha256::digest(&data);
    if checksum != digest.to_vec() {
        return Err(Error::ArchiveChecksumMismatch(name.to_string()));
    }
    let summary = Header::read_summary_slice(&data).await?;
    Ok((summary, data))
}

async fn archive_buffer(
    reader: &mut ZipReader<BufReader<File>>,
    name: &str,
    checksum: Vec<u8>,
) -> Result<Vec<u8>> {
    let data = reader.by_name(name).await?.unwrap();
    let digest = Sha256::digest(&data);
    if checksum != digest.to_vec() {
        return Err(Error::ArchiveChecksumMismatch(name.to_string()));
    }
    Ok(data)
}
