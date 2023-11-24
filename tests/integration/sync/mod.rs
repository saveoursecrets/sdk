use crate::test_utils::{create_local_account, setup, TestDirs, TestServer};
use anyhow::Result;
use copy_dir::copy_dir;
use secrecy::SecretString;
use sos_net::{
    client::{Origin, RemoteBridge, RemoteSync, UserStorage},
    sdk::{
        constants::VAULT_EXT,
        vault::{Summary, VaultId},
        vfs,
    },
};
use std::path::PathBuf;

mod create_remote_data;
mod send_secret_create;
mod send_secret_delete;
mod send_secret_update;

mod send_folder_create;
mod send_folder_delete;
mod send_folder_import;
mod send_folder_rename;

mod listen_secret_create;
mod listen_secret_delete;
mod listen_secret_update;

mod listen_folder_create;
mod listen_folder_delete;
mod listen_folder_import;
mod listen_folder_rename;

mod offline_manual;
mod websocket_reconnect;

pub struct SimulatedDevice {
    pub owner: UserStorage,
    pub default_folder: Summary,
    pub folders: Vec<Summary>,
    pub origin: Origin,
    pub dirs: TestDirs,
    pub default_folder_id: VaultId,
    pub data_dir: PathBuf,
    pub server_path: PathBuf,
    pub password: SecretString,
}

impl SimulatedDevice {
    /// Connect a device at the given client path index.
    pub async fn connect(
        &self,
        index: usize,
        origin: Option<Origin>,
    ) -> Result<UserStorage> {
        let device_dir = self.dirs.clients.get(index).unwrap();
        let mut device = UserStorage::sign_in(
            self.owner.address(),
            self.password.clone(),
            None,
            Some(device_dir.clone()),
        )
        .await?;

        let origin = origin.unwrap_or_else(|| self.origin.clone());

        // Mimic account owner on another device connected to
        // the same remotes
        let other_provider = device.remote_bridge(&origin).await?;
        // Insert the remote for the other owner
        device.insert_remote(self.origin.clone(), Box::new(other_provider));

        // Must list folders to load cache into memory after sign in
        device.list_folders().await?;

        // Use the default folder
        device.open_folder(&self.default_folder).await?;

        Ok(device)
    }
}

/// Simulate a primary device.
pub async fn simulate_device(
    test_id: &str,
    server: &TestServer,
    num_clients: usize,
) -> Result<SimulatedDevice> {
    let dirs = setup(test_id, num_clients).await?;
    let data_dir = dirs.clients.get(0).unwrap().clone();

    let (mut owner, _, default_folder, password) =
        create_local_account(test_id, Some(data_dir.clone())).await?;

    // Folders on the local account must be loaded into memory
    let folders: Vec<Summary> = {
        let storage = owner.storage();
        let mut writer = storage.write().await;
        writer
            .load_vaults()
            .await?
            .into_iter()
            .map(|s| s.clone())
            .collect()
    };

    // Copy the initial data directory for the
    // alternative devices as they need to share
    // exactly the same initial data
    for index in 1..dirs.clients.len() {
        let dir = dirs.clients.get(index).unwrap();
        std::fs::remove_dir(&dir)?;
        copy_dir(&data_dir, &dir)?;
    }

    //let original_summaries_len = expected_summaries.len();

    /*
    // Path that we expect the remote server to write to
    let server_path = server.account_path(owner.address());
    */

    // Create the remote provider
    let origin = server.origin.clone();
    let provider = owner.remote_bridge(&origin).await?;

    // Insert the remote for the primary owner
    owner.insert_remote(origin.clone(), Box::new(provider));

    //let default_folder_id = *default_folder.id();
    owner.open_folder(&default_folder).await?;

    // Sync the local account to create the account on remote
    owner.sync().await?;

    let server_path = server.account_path(owner.address());
    let default_folder_id = *default_folder.id();

    Ok(SimulatedDevice {
        owner,
        default_folder,
        folders,
        origin,
        dirs,
        server_path,
        default_folder_id,
        data_dir,
        password,
    })
}

/// Get the number of events in a log.
pub async fn num_events(owner: &mut UserStorage, folder: &VaultId) -> usize {
    let storage = owner.storage();
    let reader = storage.read().await;
    let events = reader.cache().get(folder).unwrap();
    events.tree().len()
}

/// Assert that local and remote storage are equal.
///
/// Note that this assertion can only be performed
/// when no secrets have been added to the vault
/// as the server vault does not contain secrets,
/// it only maintains data in the event log and
/// uses a header-only vault just to keep track of
/// the summary etc.
pub async fn assert_local_remote_vaults_eq(
    expected_summaries: Vec<Summary>,
    server_path: &PathBuf,
    owner: &mut UserStorage,
    provider: &mut RemoteBridge,
) -> Result<()> {
    let storage = owner.storage();
    let reader = storage.read().await;

    // Compare vault buffers
    for summary in expected_summaries {
        let local_folder = reader.vault_path(&summary);
        let remote_folder =
            server_path.join(format!("{}.{}", summary.id(), VAULT_EXT));
        let local_buffer = vfs::read(&local_folder).await?;
        let remote_buffer = vfs::read(&remote_folder).await?;
        assert_eq!(local_buffer, remote_buffer);
    }

    Ok(())
}

pub async fn assert_local_remote_events_eq(
    expected_summaries: Vec<Summary>,
    owner: &mut UserStorage,
    provider: &mut RemoteBridge,
) -> Result<()> {
    let storage = owner.storage();

    // Compare event log status (commit proofs)
    let local_status = {
        let mut writer = storage.write().await;
        writer.account_status().await?
    };
    let remote_status = provider.account_status().await?;

    //println!("{:#?}", local_status);
    //println!("{:#?}", remote_status);

    assert_eq!(local_status, remote_status);

    Ok(())
}
