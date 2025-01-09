//! Folder implementation backed by the filesystem.
use super::GenericFolder;
use crate::reducers::FolderReducer;
use sos_core::events::EventLog;
use sos_core::{constants::EVENT_LOG_EXT, decode};
use sos_filesystem::{
    events::FolderEventLog, Error, FileSystemGateKeeper, VaultFileWriter,
};
use sos_vault::Vault;
use sos_vfs as vfs;
use std::{path::Path, sync::Arc};
use tokio::sync::RwLock;

/// Folder that writes events to disc.
pub type DiscFolder = GenericFolder<FolderEventLog, Error>;

impl GenericFolder<FolderEventLog, Error> {
    /// Create a new folder from a vault file on disc.
    ///
    /// Changes to the in-memory vault are mirrored to disc and
    /// and if an event log does not exist it is created.
    pub async fn new(
        path: impl AsRef<Path>,
    ) -> Result<Self, sos_filesystem::Error> {
        let mut events_path = path.as_ref().to_owned();
        events_path.set_extension(EVENT_LOG_EXT);

        let mut event_log = FolderEventLog::new(events_path).await?;
        event_log.load_tree().await?;
        let needs_init = event_log.tree().root().is_none();

        let vault = if needs_init {
            // For the client-side we must split the events
            // out but keep the existing vault data (not the head-only)
            // version so that the event log here will match what the
            // server will have when an account is first synced
            let buffer = vfs::read(path.as_ref()).await?;
            let vault: Vault = decode(&buffer).await?;
            let (_, events) =
                FolderReducer::split::<Error>(vault.clone()).await?;
            event_log.apply(events.iter().collect()).await?;
            vault
        } else {
            let buffer = vfs::read(path.as_ref()).await?;
            let vault: Vault = decode(&buffer).await?;
            vault
        };

        let mirror = VaultFileWriter::new(path.as_ref()).await?;
        let keeper =
            FileSystemGateKeeper::new_mirror(vault, Box::new(mirror));

        Ok(Self::init(keeper, event_log))
    }

    /// Load an identity folder event log from the given paths.
    pub async fn new_event_log(
        path: impl AsRef<Path>,
    ) -> Result<Arc<RwLock<FolderEventLog>>, sos_filesystem::Error> {
        let mut event_log =
            FolderEventLog::new(path.as_ref().to_owned()).await?;
        event_log.load_tree().await?;
        Ok(Arc::new(RwLock::new(event_log)))
    }
}

impl From<GenericFolder<FolderEventLog, sos_filesystem::Error>> for Vault {
    fn from(
        value: GenericFolder<FolderEventLog, sos_filesystem::Error>,
    ) -> Self {
        value.keeper.into()
    }
}
