use crate::{setup, TestDirs, TestServer};
use anyhow::Result;
use copy_dir::copy_dir;
use secrecy::SecretString;
use sos_net::{
    client::{
        ListenOptions, NetworkAccount, Origin, RemoteBridge, RemoteSync,
        WebSocketHandle,
    },
    sdk::{
        constants::{FILES_DIR, VAULT_EXT},
        crypto::AccessKey,
        events::EventLogExt,
        passwd::diceware::generate_passphrase,
        storage::files::ExternalFile,
        sync::{Client, SyncStorage},
        vault::{Summary, VaultId},
        vfs, Paths,
    },
};
use std::path::PathBuf;

pub struct SimulatedDevice {
    pub id: String,
    pub owner: NetworkAccount,
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
    ) -> Result<SimulatedDevice> {
        let data_dir = self.dirs.clients.get(index).unwrap();

        let mut owner = NetworkAccount::new_unauthenticated(
            self.owner.address().clone(),
            Some(data_dir.clone()),
            None,
        )
        .await?;

        let connection_id = format!("device_{}", index + 1);
        owner.set_connection_id(Some(connection_id.clone()));

        let key: AccessKey = self.password.clone().into();
        owner.sign_in(&key).await?;

        let origin = origin.unwrap_or_else(|| self.origin.clone());

        // Mimic account owner on another owner connected to
        // the same remotes
        let provider = owner.remote_bridge(&origin).await?;
        // Insert the remote for the other owner
        owner
            .insert_remote(self.origin.clone().into(), Box::new(provider))
            .await?;

        // Use the default folder
        owner.open_folder(&self.default_folder).await?;

        Ok(SimulatedDevice {
            id: connection_id,
            owner,
            data_dir: data_dir.clone(),
            default_folder: self.default_folder.clone(),
            default_folder_id: self.default_folder_id.clone(),
            folders: self.folders.clone(),
            origin: origin.clone(),
            dirs: self.dirs.clone(),
            server_path: self.server_path.clone(),
            password: self.password.clone(),
        })
    }

    /// Start listening for changes.
    pub async fn listen(&self) -> Result<WebSocketHandle> {
        Ok(self
            .owner
            .listen(&self.origin, ListenOptions::new(self.id.clone())?)
            .await?)
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

    let (password, _) = generate_passphrase()?;
    let mut owner = NetworkAccount::new_account(
        test_id.to_owned(),
        password.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    let connection_id = "device_1".to_string();
    owner.set_connection_id(Some(connection_id.clone()));

    let key: AccessKey = password.clone().into();
    let folders = owner.sign_in(&key).await?;
    let default_folder = owner.default_folder().await.unwrap();

    // Copy the initial data directory for the
    // alternative devices as they need to share
    // exactly the same initial data
    for index in 1..dirs.clients.len() {
        let dir = dirs.clients.get(index).unwrap();
        std::fs::remove_dir(&dir)?;
        copy_dir(&data_dir, &dir)?;
    }

    // Create the remote provider
    let origin = server.origin.clone();
    let provider = owner.remote_bridge(&origin).await?;

    // Insert the remote for the primary owner
    owner
        .insert_remote(origin.clone().into(), Box::new(provider))
        .await?;

    // Sync the local account to create the account on remote
    let sync_error = owner.sync().await;
    assert!(sync_error.is_none());

    let server_path = server.account_path(owner.address());
    let default_folder_id = *default_folder.id();

    Ok(SimulatedDevice {
        id: connection_id,
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
pub async fn num_events(
    owner: &mut NetworkAccount,
    folder_id: &VaultId,
) -> usize {
    let storage = owner.storage().await.unwrap();
    let reader = storage.read().await;
    let folder = reader.cache().get(folder_id).unwrap();
    let events = folder.event_log();
    let events = events.read().await;
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
    owner: &mut NetworkAccount,
    _provider: &mut RemoteBridge,
) -> Result<()> {
    let storage = owner.storage().await?;
    let reader = storage.read().await;

    // Compare vault buffers
    for summary in expected_summaries {
        tracing::debug!(id = %summary.id(), "assert_local_remote_vaults_eq");

        let local_folder = reader.paths().vault_path(summary.id());
        let remote_folder = server_path.join("vaults").join(format!(
            "{}.{}",
            summary.id(),
            VAULT_EXT
        ));

        let local_buffer = vfs::read(&local_folder).await?;
        let remote_buffer = vfs::read(&remote_folder).await?;
        assert_eq!(local_buffer, remote_buffer);
    }

    Ok(())
}

pub async fn assert_local_remote_events_eq(
    _expected_summaries: Vec<Summary>,
    owner: &mut NetworkAccount,
    provider: &mut RemoteBridge,
) -> Result<()> {
    use pretty_assertions::assert_eq;

    // Compare event log status (commit proofs)
    let local_status = owner.sync_status().await?;
    let remote_status = provider.client().sync_status().await?.unwrap();

    //println!(" local {:#?}", local_status);
    //println!("remote {:#?}", remote_status);

    assert_eq!(local_status, remote_status);

    Ok(())
}

pub async fn assert_local_remote_file_eq(
    local_paths: &Paths,
    server_path: &PathBuf,
    file: &ExternalFile,
) -> Result<()> {
    let expected_client_file = local_paths.file_location(
        file.vault_id(),
        file.secret_id(),
        file.file_name().to_string(),
    );
    let expected_server_file = server_path
        .join(FILES_DIR)
        .join(file.vault_id().to_string())
        .join(file.secret_id().to_string())
        .join(file.file_name().to_string());

    //println!("client {:#?}", expected_client_file);
    //println!("server {:#?}", expected_server_file);

    if !vfs::try_exists(&expected_client_file).await? {
        eprintln!("expected_client_file {:#?}", expected_client_file);
    }
    if !vfs::try_exists(&expected_server_file).await? {
        eprintln!("expected_server_file {:#?}", expected_server_file);
    }

    assert!(vfs::try_exists(&expected_client_file).await?);
    assert!(vfs::try_exists(&expected_server_file).await?);

    let client_file = vfs::read(&expected_client_file).await?;
    let server_file = vfs::read(&expected_server_file).await?;
    assert_eq!(client_file, server_file);

    Ok(())
}

/// Wait for file transfers to complete.
pub async fn wait_for_transfers(account: &NetworkAccount) -> Result<()> {
    loop {
        let transfers = account.transfers().await?;
        let transfers = transfers.read().await;
        if transfers.is_empty() {
            break;
        }
    }
    Ok(())
}
