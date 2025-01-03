use crate::{setup, TestDirs, TestServer};
use anyhow::Result;
use copy_dir::copy_dir;
use secrecy::SecretString;
use sos_net::{
    protocol::{
        network_client::{ListenOptions, HttpClient}, AccountSync, Origin,
        RemoteSyncHandler, SyncClient, SyncStorage,
    },
    sdk::{
        account::{Account, AccountBuilder},
        constants::{FILES_DIR, VAULT_EXT},
        crypto::AccessKey,
        events::EventLogExt,
        passwd::diceware::generate_passphrase,
        sha2::{Digest, Sha256},
        storage::files::ExternalFile,
        url::Url,
        vault::{Summary, VaultId},
        vfs, Paths,
    },
    InflightNotification, InflightTransfers, NetworkAccount, RemoteBridge,
};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::Mutex;

/// Wait for a number of websocket connections to be reported 
/// by a server.
pub async fn wait_num_websocket_connections(origin: &Origin, target: usize) -> anyhow::Result<()> {
    #[allow(unused_assignments)]
    let mut num_conns = 0;
    loop {
        num_conns = HttpClient::num_connections(origin.url()).await?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        if num_conns == target {
            break;
        }
    }
    Ok(())
}


/// Simulated device information.
pub struct SimulatedDevice {
    /// Test identifier for the device.
    pub id: String,
    /// Network account.
    pub owner: NetworkAccount,
    /// Default folder.
    pub default_folder: Summary,
    /// Folders when the account was created.
    pub folders: Vec<Summary>,
    /// Origin for a remote server.
    pub origin: Origin,
    /// Directories for test data.
    pub dirs: TestDirs,
    /// Default folder identifier.
    pub default_folder_id: VaultId,
    /// Data storage directory.
    pub data_dir: PathBuf,
    /// Path to the server data directory.
    pub server_path: PathBuf,
    /// Password used for account creation.
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
            Default::default(),
        )
        .await?;

        let connection_id = format!("device_{}", index + 1);
        owner.set_connection_id(Some(connection_id.clone()));

        let key: AccessKey = self.password.clone().into();
        owner.sign_in(&key).await?;

        let origin = origin.unwrap_or_else(|| self.origin.clone());

        // Mimic account owner on another owner connected to
        // the same remotes
        owner.add_server(origin.clone()).await?;

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
    pub async fn listen(&self) -> Result<()> {
        Ok(self
            .owner
            .listen(&self.origin, ListenOptions::new(self.id.clone())?, None)
            .await?)
    }
}

/// Simulate a device using the given account builder.
pub async fn simulate_device_with_builder(
    test_id: &str,
    num_clients: usize,
    server: Option<&TestServer>,
    builder: impl Fn(AccountBuilder) -> AccountBuilder + Send,
) -> Result<SimulatedDevice> {
    let dirs = setup(test_id, num_clients).await?;
    let data_dir = dirs.clients.get(0).unwrap().clone();

    let (password, _) = generate_passphrase()?;
    let mut owner = NetworkAccount::new_account_with_builder(
        test_id.to_owned(),
        password.clone(),
        Some(data_dir.clone()),
        Default::default(),
        builder,
    )
    .await?;

    let connection_id = "device_1".to_string();
    owner.set_connection_id(Some(connection_id.clone()));

    let key: AccessKey = password.clone().into();
    let folders = owner.sign_in(&key).await?;
    let default_folder = owner.default_folder().await.unwrap();
    let default_folder_id = *default_folder.id();

    // Copy the initial data directory for the
    // alternative devices as they need to share
    // exactly the same initial data
    for index in 1..dirs.clients.len() {
        let dir = dirs.clients.get(index).unwrap();
        std::fs::remove_dir(&dir)?;
        copy_dir(&data_dir, &dir)?;
    }

    // Create the remote provider
    let (origin, server_path) = if let Some(server) = server {
        let origin = server.origin.clone();
        owner.add_server(origin.clone()).await?;

        // Sync the local account to create the account on remote
        let sync_result = owner.sync().await;
        assert!(sync_result.first_error().is_none());

        (origin, server.account_path(owner.address()))
    } else {
        let url: Url = "https://example.com".parse()?;
        (url.into(), PathBuf::new())
    };

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

/// Simulate a primary device.
///
/// If a server is given the device will be connected to
/// the given server.
pub async fn simulate_device(
    test_id: &str,
    num_clients: usize,
    server: Option<&TestServer>,
) -> Result<SimulatedDevice> {
    simulate_device_with_builder(test_id, num_clients, server, |builder| {
        builder.create_file_password(true)
    })
    .await
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

/// Assert that local and remote vault files are equal.
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
    let storage = owner
        .storage()
        .await
        .ok_or(sos_net::sdk::Error::NoStorage)?;
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

/// Compare events between a local account and a server
/// and assert they are equal.
pub async fn assert_local_remote_events_eq(
    _expected_summaries: Vec<Summary>,
    owner: &mut NetworkAccount,
    provider: &mut RemoteBridge,
) -> Result<()> {
    use pretty_assertions::assert_eq;

    // Compare event log status (commit proofs)
    let local_status = owner.sync_status().await?;
    let remote_status =
        provider.client().sync_status(owner.address()).await?;

    //println!(" local {:#?}", local_status);
    //println!("remote {:#?}", remote_status);

    assert_eq!(local_status, remote_status);

    Ok(())
}

/// Compare local and remote file and assert they are equal.
pub async fn assert_local_remote_file_eq(
    local_paths: impl AsRef<Paths>,
    server_path: &PathBuf,
    file: &ExternalFile,
) -> Result<()> {
    let expected_client_file = local_paths.as_ref().file_location(
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

/// Assert that both a local and remote file do not exist.
pub async fn assert_local_remote_file_not_exist(
    local_paths: impl AsRef<Paths>,
    server_path: &PathBuf,
    file: &ExternalFile,
) -> Result<()> {
    let expected_client_file = local_paths.as_ref().file_location(
        file.vault_id(),
        file.secret_id(),
        file.file_name().to_string(),
    );
    let expected_server_file = server_path
        .join(FILES_DIR)
        .join(file.vault_id().to_string())
        .join(file.secret_id().to_string())
        .join(file.file_name().to_string());

    assert!(!vfs::try_exists(expected_client_file).await?);
    assert!(!vfs::try_exists(expected_server_file).await?);

    Ok(())
}

/// Wait for the number of transfers to complete.
pub async fn wait_for_num_transfers(
    account: &NetworkAccount,
    amount: u16,
) -> Result<()> {
    let inflight = account.inflight_transfers()?;
    wait_for_inflight(
        Arc::clone(&inflight),
        |event| matches!(event, InflightNotification::TransferDone { .. }),
        move |num| num == amount,
    )
    .await;
    Ok(())
}

/// Wait for inflight notifications.
pub async fn wait_for_inflight(
    inflight: Arc<InflightTransfers>,
    increment: impl Fn(InflightNotification) -> bool + Send + Sync + 'static,
    is_complete: impl Fn(u16) -> bool + Send + Sync + 'static,
) {
    let mut inflight_rx = inflight.notifications().subscribe();
    let num_events = Mutex::new(0u16);

    loop {
        tokio::select! {
          event = inflight_rx.recv() => {
            if let Ok(event) = event {
                // println!("event: {:#?}", event);
                if increment(event) {
                    let mut num = num_events.lock().await;
                    *num += 1;
                }
                let num = num_events.lock().await;
                if is_complete(*num) {
                  println!("wait_for_inflight::finished");
                  break;
                }
            }
          }
        }
    }
}

/// Wait for a file to exist whose content matches
/// the file name checksum.
pub async fn wait_for_file(
    paths: impl AsRef<Paths>,
    file: &ExternalFile,
) -> Result<()> {
    let path = paths.as_ref().file_location(
        file.vault_id(),
        file.secret_id(),
        file.file_name().to_string(),
    );
    wait_for_cond(move || {
        if path.exists() {
            let contents = std::fs::read(&path).unwrap();
            let checksum = Sha256::digest(&contents);
            if checksum.as_slice() == file.file_name().as_ref() {
                true
            } else {
                false
            }
        } else {
            false
        }
    })
    .await;
    Ok(())
}

/// Wait for a file to not exist.
pub async fn wait_for_file_not_exist(
    paths: impl AsRef<Paths>,
    file: &ExternalFile,
) -> Result<()> {
    wait_for_cond(move || {
        let path = paths.as_ref().file_location(
            file.vault_id(),
            file.secret_id(),
            file.file_name().to_string(),
        );
        !path.exists()
    })
    .await;
    Ok(())
}

/// Wait for a condition to be met.
pub async fn wait_for_cond<T>(test: T)
where
    T: Fn() -> bool,
{
    let timeout = Duration::from_millis(15000);
    let start = SystemTime::now();

    loop {
        let elapsed = start.elapsed().unwrap();
        if elapsed > timeout {
            panic!(
                "wait condition took too long, timeout {:?} exceeded",
                timeout
            );
        }
        let done = test();
        if done {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
