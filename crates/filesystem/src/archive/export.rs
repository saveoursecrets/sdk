//! Export an account backup archive.
use crate::archive::{Error, ManifestVersion1, Result};
use hex;
use sha2::{Digest, Sha256};
use sos_archive::ZipWriter;
use sos_core::{
    constants::{
        ACCOUNT_EVENTS, DEVICE_FILE, EVENT_LOG_EXT, FILE_EVENTS, JSON_EXT,
        PREFERENCES_FILE, REMOTES_FILE, VAULT_EXT,
    },
    AccountId, Paths, VaultId,
};
use sos_vault::list_local_folders;
use sos_vfs as vfs;
use std::{
    io::Cursor,
    path::{Path, PathBuf},
};

/// Export an archive of the account to disc.
pub async fn export_backup_archive<P: AsRef<Path>>(
    path: P,
    address: &AccountId,
    paths: &Paths,
) -> Result<()> {
    let buffer = export_archive_buffer(address, paths).await?;
    vfs::write(path.as_ref(), buffer).await?;
    Ok(())
}

/// Create a buffer for a zip archive including the
/// identity vault and all user vaults.
async fn export_archive_buffer(
    address: &AccountId,
    paths: &Paths,
) -> Result<Vec<u8>> {
    let identity_path = paths.identity_vault();
    if !vfs::try_exists(&identity_path).await? {
        return Err(Error::NotFile(identity_path));
    }
    let identity = vfs::read(identity_path).await?;

    let vaults = list_local_folders(paths).await?;

    let mut archive = Vec::new();
    let mut writer =
        ZipWriter::new(Cursor::new(&mut archive), ManifestVersion1::new_v2());
    set_identity(&mut writer, address, &identity).await?;

    for (summary, path) in vaults {
        let buffer = vfs::read(path).await?;
        add_vault(&mut writer, *summary.id(), &buffer).await?;
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
        add_devices(&mut writer, vault.as_slice(), events.as_slice()).await?;
    }

    if vfs::try_exists(paths.account_events()).await? {
        let buffer = vfs::read(paths.account_events()).await?;
        add_account_events(&mut writer, buffer.as_slice()).await?;
    }

    if vfs::try_exists(paths.file_events()).await? {
        let buffer = vfs::read(paths.file_events()).await?;
        add_file_events(&mut writer, buffer.as_slice()).await?;
    }

    if vfs::try_exists(paths.preferences_file()).await? {
        let buffer = vfs::read(paths.preferences_file()).await?;
        add_preferences(&mut writer, buffer.as_slice()).await?;
    }

    if vfs::try_exists(paths.remote_origins()).await? {
        let buffer = vfs::read(paths.remote_origins()).await?;
        add_remote_servers(&mut writer, buffer.as_slice()).await?;
    }

    let external_files =
        sos_external_files::list_external_files(paths).await?;
    for file in &external_files {
        let relative = PathBuf::from("files").join(file.to_string());
        let buffer = vfs::read(paths.into_file_path(file)).await?;
        writer
            .add_file(relative.to_string_lossy().as_ref(), &buffer)
            .await?;
    }

    writer.finish().await?;
    Ok(archive)
}

/// Set the identity vault for the archive.
async fn set_identity(
    writer: &mut ZipWriter<Cursor<&mut Vec<u8>>, ManifestVersion1>,
    account_id: &AccountId,
    vault: &[u8],
) -> Result<()> {
    let mut path = PathBuf::from(account_id.to_string());
    path.set_extension(VAULT_EXT);

    writer.manifest_mut().account_id = *account_id;
    writer.manifest_mut().checksum =
        hex::encode(Sha256::digest(vault).as_slice());
    writer
        .add_file(path.to_string_lossy().as_ref(), vault)
        .await?;

    Ok(())
}

/// Add a vault to the archive.
async fn add_vault(
    writer: &mut ZipWriter<Cursor<&mut Vec<u8>>, ManifestVersion1>,
    vault_id: VaultId,
    vault: &[u8],
) -> Result<()> {
    let mut path = PathBuf::from(vault_id.to_string());
    path.set_extension(VAULT_EXT);

    let checksum = hex::encode(Sha256::digest(vault).as_slice());
    writer.manifest_mut().vaults.insert(vault_id, checksum);
    writer
        .add_file(path.to_string_lossy().as_ref(), vault)
        .await?;

    Ok(())
}

/// Add a devices vault to the archive.
async fn add_devices(
    writer: &mut ZipWriter<Cursor<&mut Vec<u8>>, ManifestVersion1>,
    vault: &[u8],
    events: &[u8],
) -> Result<()> {
    let vault_checksum = hex::encode(Sha256::digest(vault).as_slice());
    let event_checksum = hex::encode(Sha256::digest(events).as_slice());
    writer.manifest_mut().devices = Some((vault_checksum, event_checksum));

    // Create the device vault file
    let mut path = PathBuf::from(DEVICE_FILE);
    path.set_extension(VAULT_EXT);
    writer
        .add_file(path.to_string_lossy().as_ref(), vault)
        .await?;

    // Create the device events file
    let mut path = PathBuf::from(DEVICE_FILE);
    path.set_extension(EVENT_LOG_EXT);
    writer
        .add_file(path.to_string_lossy().as_ref(), events)
        .await?;

    Ok(())
}

/// Add account events to the archive.
async fn add_account_events(
    writer: &mut ZipWriter<Cursor<&mut Vec<u8>>, ManifestVersion1>,
    events: &[u8],
) -> Result<()> {
    let event_checksum = hex::encode(Sha256::digest(events).as_slice());
    writer.manifest_mut().account = Some(event_checksum);

    // Create the account events file
    let mut path = PathBuf::from(ACCOUNT_EVENTS);
    path.set_extension(EVENT_LOG_EXT);
    writer
        .add_file(path.to_string_lossy().as_ref(), events)
        .await?;

    Ok(())
}

/// Add file events to the archive.
async fn add_file_events(
    writer: &mut ZipWriter<Cursor<&mut Vec<u8>>, ManifestVersion1>,
    events: &[u8],
) -> Result<()> {
    let event_checksum = hex::encode(Sha256::digest(events).as_slice());
    writer.manifest_mut().files = Some(event_checksum);

    // Create the file events file
    let mut path = PathBuf::from(FILE_EVENTS);
    path.set_extension(EVENT_LOG_EXT);
    writer
        .add_file(path.to_string_lossy().as_ref(), events)
        .await?;

    Ok(())
}

/// Add account-specific preferences.
async fn add_preferences(
    writer: &mut ZipWriter<Cursor<&mut Vec<u8>>, ManifestVersion1>,
    prefs: &[u8],
) -> Result<()> {
    let checksum = hex::encode(Sha256::digest(prefs).as_slice());
    writer.manifest_mut().preferences = Some(checksum);

    // Create the file events file
    let mut path = PathBuf::from(PREFERENCES_FILE);
    path.set_extension(JSON_EXT);

    writer
        .add_file(path.to_string_lossy().as_ref(), prefs)
        .await?;

    Ok(())
}

/// Add remote server settings.
async fn add_remote_servers(
    writer: &mut ZipWriter<Cursor<&mut Vec<u8>>, ManifestVersion1>,
    remotes: &[u8],
) -> Result<()> {
    let checksum = hex::encode(Sha256::digest(remotes).as_slice());
    writer.manifest_mut().remotes = Some(checksum);

    // Create the file events file
    let mut path = PathBuf::from(REMOTES_FILE);
    path.set_extension(JSON_EXT);

    writer
        .add_file(path.to_string_lossy().as_ref(), remotes)
        .await?;

    Ok(())
}
