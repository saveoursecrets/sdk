use super::{Error, Result, types::ManifestVersion3};
use crate::entity::{
    AccountEntity, AccountRecord, AccountRow, EventEntity, EventRecordRow,
    FolderEntity, FolderRow, PreferenceEntity, PreferenceRow, SecretRow,
    ServerEntity, ServerRow, SystemMessageEntity, SystemMessageRow,
};
use async_sqlite::rusqlite::Connection;
use sha2::{Digest, Sha256};
use sos_archive::{ZipReader, sanitize_file_path};
use sos_core::{
    AccountId, ExternalFile, ExternalFileName, Paths, SecretId, SecretPath,
    VaultId,
    commit::CommitHash,
    constants::{BLOBS_DIR, DATABASE_FILE},
    events::EventLogType,
};
use sos_vfs as vfs;
use std::{
    collections::HashMap,
    io::{self, BufWriter, Write},
    path::Path,
};
use tempfile::NamedTempFile;
use tokio::io::BufReader;

struct HashingWriter<W: Write, H: Digest> {
    inner: W,
    hasher: H,
}

impl<W: Write, H: Digest> Write for HashingWriter<W, H> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hasher.update(buf);
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Data source for an account import.
struct ImportDataSource {
    account_row: AccountRow,
    account_events: Vec<EventRecordRow>,
    login_folder: (FolderRow, Vec<SecretRow>, Vec<EventRecordRow>),
    device_folder: Option<(FolderRow, Vec<SecretRow>, Vec<EventRecordRow>)>,
    user_folders: Vec<(FolderRow, Vec<SecretRow>, Vec<EventRecordRow>)>,
    file_events: Vec<EventRecordRow>,
    servers: Vec<ServerRow>,
    account_preferences: Vec<PreferenceRow>,
    system_messages: Vec<SystemMessageRow>,
}

/// Backup import.
pub struct BackupImport {
    // Box the connection so it implements Deref<Target = Connection>
    // which database entities use so they can accept transactions
    source_db: Box<Connection>,
    target_db: Box<Connection>,
    paths: Paths,
    #[allow(dead_code)]
    manifest: ManifestVersion3,
    // Ensure the temp file is not deleted
    // until this struct is dropped
    #[allow(dead_code)]
    db_temp: NamedTempFile,
    blobs: HashMap<AccountId, Vec<ExternalFile>>,
    zip_reader: ZipReader<BufReader<vfs::File>>,
}

impl BackupImport {
    /// List accounts in the temporary source database.
    pub fn list_source_accounts(&self) -> Result<Vec<AccountRecord>> {
        let accounts = AccountEntity::new(&self.source_db);
        let rows = accounts.list_accounts()?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row.try_into()?);
        }
        Ok(records)
    }

    /// List accounts in the target database.
    pub fn list_target_accounts(&self) -> Result<Vec<AccountRecord>> {
        let accounts = AccountEntity::new(&self.target_db);
        let rows = accounts.list_accounts()?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row.try_into()?);
        }
        Ok(records)
    }

    /// Run migrations on the temporary source database.
    pub fn migrate_source(&mut self) -> Result<refinery::Report> {
        Ok(crate::migrations::migrate_connection(&mut self.source_db)?)
    }

    /// Run migrations on the target database.
    pub fn migrate_target(&mut self) -> Result<refinery::Report> {
        Ok(crate::migrations::migrate_connection(&mut self.target_db)?)
    }

    /// Try to import an account from the source to the
    /// target database.
    ///
    /// It is an error if the account already exists in
    /// the target database.
    pub async fn import_account(
        &mut self,
        record: &AccountRecord,
    ) -> Result<()> {
        // Check account exists in the source db
        let account_row = {
            let accounts = AccountEntity::new(&self.source_db);
            let account =
                accounts.find_optional(record.identity.account_id())?;

            let Some(account_row) = account else {
                return Err(Error::ImportSourceNotExists(
                    *record.identity.account_id(),
                ));
            };

            account_row
        };

        // Check account does not exist in target
        {
            let accounts = AccountEntity::new(&self.target_db);
            let target_account =
                accounts.find_optional(record.identity.account_id())?;

            if target_account.is_some() {
                return Err(Error::ImportTargetExists(
                    *record.identity.account_id(),
                ));
            }
        }

        let account_paths =
            self.paths.with_account_id(record.identity.account_id());

        // Read data from the source db
        let data_source = self.read_import_data_source(account_row)?;

        // Write data to the target db
        self.write_import_data_source(data_source)?;

        // Extract blobs for this account
        if let Some(files) = self.blobs.get(record.identity.account_id()) {
            for file in files {
                let entry_name = format!(
                    "{}/{}/{}/{}/{}",
                    BLOBS_DIR,
                    record.identity.account_id(),
                    file.vault_id(),
                    file.secret_id(),
                    file.file_name(),
                );
                let target = account_paths.into_file_path(file);
                let blob_buffer =
                    self.zip_reader.by_name(&entry_name).await?.unwrap();

                if let Some(parent) = target.parent() {
                    vfs::create_dir_all(parent).await?;
                }
                vfs::write(&target, &blob_buffer).await?;
            }
        }

        Ok(())
    }

    /// Read import data into memory from the source db.
    fn read_import_data_source(
        &self,
        account_row: AccountRow,
    ) -> Result<ImportDataSource> {
        let account_id = account_row.row_id;

        let folder_entity = FolderEntity::new(&self.source_db);
        let event_entity = EventEntity::new(&self.source_db);
        let server_entity = ServerEntity::new(&self.source_db);
        let preference_entity = PreferenceEntity::new(&self.source_db);
        let system_messages_entity =
            SystemMessageEntity::new(&self.source_db);

        // Account events
        let account_events = event_entity.load_events(
            EventLogType::Account,
            account_id,
            None,
        )?;

        // Login folder
        let login_folder = folder_entity.find_login_folder(account_id)?;
        let login_secrets =
            folder_entity.load_secrets(login_folder.row_id)?;
        let login_events = event_entity.load_events(
            EventLogType::Identity,
            account_id,
            Some(login_folder.row_id),
        )?;

        // Device folder
        let device_folder = folder_entity.find_device_folder(account_id)?;
        let device_folder = if let Some(device_folder) = device_folder {
            let device_events = event_entity.load_events(
                EventLogType::Identity,
                account_id,
                Some(device_folder.row_id),
            )?;
            let device_secrets =
                folder_entity.load_secrets(device_folder.row_id)?;
            Some((device_folder, device_secrets, device_events))
        } else {
            None
        };

        // User defined folders
        let folders = folder_entity.list_user_folders(account_id)?;
        let mut user_folders = Vec::new();
        for user_folder in folders {
            let folder_events = event_entity.load_events(
                EventLogType::Identity,
                account_id,
                Some(user_folder.row_id),
            )?;
            let folder_secrets =
                folder_entity.load_secrets(user_folder.row_id)?;
            user_folders.push((user_folder, folder_secrets, folder_events));
        }

        // File events
        let file_events = event_entity.load_events(
            EventLogType::Files,
            account_id,
            None,
        )?;

        // Servers, preferences and system messages
        let servers = server_entity.load_servers(account_id)?;
        let account_preferences =
            preference_entity.load_preferences(Some(account_id))?;
        let system_messages =
            system_messages_entity.load_system_messages(account_id)?;

        // Data source
        let data_source = ImportDataSource {
            account_row,
            account_events,
            login_folder: (login_folder, login_secrets, login_events),
            device_folder,
            user_folders,
            file_events,
            servers,
            account_preferences,
            system_messages,
        };

        Ok(data_source)
    }

    /// Write import data source into the target db using a transaction.
    fn write_import_data_source(
        &mut self,
        data: ImportDataSource,
    ) -> Result<()> {
        let tx = self.target_db.transaction()?;

        let account_entity = AccountEntity::new(&tx);
        let folder_entity = FolderEntity::new(&tx);
        let event_entity = EventEntity::new(&tx);
        let server_entity = ServerEntity::new(&tx);
        let preference_entity = PreferenceEntity::new(&tx);
        let system_messages_entity = SystemMessageEntity::new(&tx);

        // Insert the account
        let account_id = account_entity.insert(&data.account_row)?;

        // Create account events
        event_entity
            .insert_account_events(account_id, &data.account_events)?;

        // Login folder
        let login_folder_id =
            folder_entity.insert_folder(account_id, &data.login_folder.0)?;
        folder_entity
            .insert_folder_secrets(login_folder_id, &data.login_folder.1)?;
        event_entity
            .insert_folder_events(login_folder_id, &data.login_folder.2)?;
        account_entity.insert_login_folder(account_id, login_folder_id)?;

        // Device folder
        if let Some((device_folder, device_secrets, device_events)) =
            &data.device_folder
        {
            let device_folder_id =
                folder_entity.insert_folder(account_id, device_folder)?;
            folder_entity
                .insert_folder_secrets(device_folder_id, device_secrets)?;
            event_entity
                .insert_device_events(device_folder_id, device_events)?;
            account_entity
                .insert_device_folder(account_id, device_folder_id)?;
        }

        // User folders
        for (folder, secrets, events) in &data.user_folders {
            let folder_id =
                folder_entity.insert_folder(account_id, folder)?;
            folder_entity.insert_folder_secrets(folder_id, secrets)?;
            event_entity.insert_folder_events(folder_id, events)?;
        }

        // Create file events
        event_entity.insert_file_events(account_id, &data.file_events)?;

        // Servers, preferences and system messages
        server_entity.insert_servers(account_id, &data.servers)?;
        preference_entity.insert_preferences(
            Some(account_id),
            &data.account_preferences,
        )?;
        system_messages_entity
            .insert_system_messages(account_id, &data.system_messages)?;

        tx.commit()?;

        Ok(())
    }
}

/// Start importing a backup archive.
///
/// Reads the archive manifest and extracts the archive database file
/// to a temporary file and prepares the database connections.
///
/// The returned struct will hold the temporary file and connections
/// in memory until dropped and can be used to inspect the accounts in the
/// archive and perform imports.
pub(crate) async fn start(
    // target_db: &'conn mut Connection,
    target_db: impl AsRef<Path>,
    paths: &Paths,
    input: impl AsRef<Path>,
    // progress: fn(backup::Progress),
) -> Result<BackupImport> {
    if !vfs::try_exists(input.as_ref()).await? {
        return Err(Error::ArchiveFileNotExists(input.as_ref().to_owned()));
    }

    let zip_file = BufReader::new(vfs::File::open(input.as_ref()).await?);
    let mut zip_reader = ZipReader::new(zip_file).await?;
    let manifest = zip_reader
        .find_manifest::<ManifestVersion3>()
        .await?
        .ok_or_else(|| {
            Error::InvalidArchiveManifest(input.as_ref().to_owned())
        })?;

    let blobs = find_blobs(&zip_reader)?;

    // Extract the database and write to a temp file
    let db_buffer =
        zip_reader.by_name(DATABASE_FILE).await?.ok_or_else(|| {
            Error::NoDatabaseFile(
                input.as_ref().to_owned(),
                DATABASE_FILE.to_owned(),
            )
        })?;
    let mut db_temp = NamedTempFile::new()?;

    let checksum = {
        let buf_writer = BufWriter::new(db_temp.as_file_mut());
        let mut hash_writer = HashingWriter {
            inner: buf_writer,
            hasher: Sha256::new(),
        };

        hash_writer.write_all(&db_buffer)?;
        hash_writer.flush()?;

        let digest = hash_writer.hasher.finalize();
        CommitHash(digest.as_slice().try_into()?)
    };

    if checksum != manifest.checksum {
        return Err(Error::DatabaseChecksum(manifest.checksum, checksum));
    }

    let source_db = Connection::open(db_temp.path())?;
    let target_db = Connection::open(target_db.as_ref())?;
    let import = BackupImport {
        target_db: Box::new(target_db),
        paths: paths.clone(),
        manifest,
        db_temp,
        source_db: Box::new(source_db),
        blobs,
        zip_reader,
    };

    Ok(import)
}

/// Find blobs embedded in the archive.
fn find_blobs(
    reader: &ZipReader<BufReader<vfs::File>>,
) -> Result<HashMap<AccountId, Vec<ExternalFile>>> {
    let mut out = HashMap::new();
    for index in 0..reader.inner().file().entries().len() {
        let entry = reader.inner().file().entries().get(index).unwrap();
        let is_dir = entry.dir().map_err(sos_archive::Error::from)?;
        if !is_dir {
            let file_name = entry.filename();
            let path = sanitize_file_path(
                file_name.as_str().map_err(sos_archive::Error::from)?,
            );
            let mut it = path.iter();
            if let (
                Some(first),
                Some(second),
                Some(third),
                Some(fourth),
                Some(fifth),
            ) = (it.next(), it.next(), it.next(), it.next(), it.next())
                && first == BLOBS_DIR
                && let Ok(account_id) =
                    second.to_string_lossy().parse::<AccountId>()
            {
                let files = out.entry(account_id).or_insert(Vec::new());

                if let (Ok(folder_id), Ok(secret_id), Ok(file_name)) = (
                    third.to_string_lossy().parse::<VaultId>(),
                    fourth.to_string_lossy().parse::<SecretId>(),
                    fifth.to_string_lossy().parse::<ExternalFileName>(),
                ) {
                    files.push(ExternalFile::new(
                        SecretPath(folder_id, secret_id),
                        file_name,
                    ));
                }
            }
        }
    }
    Ok(out)
}
