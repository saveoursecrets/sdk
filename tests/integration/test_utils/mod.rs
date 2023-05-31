use anyhow::Result;
use axum_server::Handle;
use secrecy::SecretString;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, thread};
use tokio::sync::{oneshot, RwLock};
use url::Url;
use web3_address::ethereum::Address;

use sos_sdk::{
    crypto::channel::SessionManager,
    events::{AuditLogFile, WriteEvent},
    vault::{
        secret::{Secret, SecretId, SecretMeta},
        Summary,
    },
    vfs,
};

use sos_net::{
    client::provider::{RemoteProvider, StorageProvider},
    server::{BackendHandler, Server, ServerConfig, ServerInfo, State},
    FileLocks,
};

const ADDR: &str = "127.0.0.1:3505";
const SERVER: &str = "http://localhost:3505";

mod signup;

pub use signup::{login, signup};

/// Encapsulates the credentials for a new account signup.
pub struct AccountCredentials {
    /// Passphrase for the vault encryption.
    pub encryption_passphrase: SecretString,
    /// Address of the signing key.
    pub address: Address,
    /// Summary that represents the login vault
    /// created when the account was created.
    pub summary: Summary,
}

struct MockServer {
    handle: Handle,
}

impl MockServer {
    fn new() -> Result<Self> {
        Ok(Self {
            handle: Handle::new(),
        })
    }

    async fn start(&self) -> Result<()> {
        let addr: SocketAddr = ADDR.parse::<SocketAddr>()?;

        tracing::info!("start mock server {:#?}", addr);

        let config = ServerConfig::load("tests/config.toml").await?;

        let mut backend = config.backend().await?;

        let mut locks = FileLocks::new();
        locks.add(config.audit_file())?;
        // Move into the backend so it can manage lock files too
        backend.handler_mut().set_file_locks(locks)?;

        // Set up the audit log
        let audit_log = AuditLogFile::new(config.audit_file()).await?;

        let state = Arc::new(RwLock::new(State {
            info: ServerInfo {
                name: String::from("integration-test"),
                version: String::from("0.0.0"),
            },
            config,
            backend,
            audit_log,
            sockets: Default::default(),
            sessions: SessionManager::new(300),
        }));

        let server = Server::new();
        server.start(addr, state, self.handle.clone()).await?;
        Ok(())
    }

    /// Run the mock server in a separate thread.
    fn spawn(tx: oneshot::Sender<SocketAddr>) -> Result<ShutdownHandle> {
        let server = MockServer::new()?;
        let listen_handle = server.handle.clone();
        let user_handle = server.handle.clone();

        thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async move {
                loop {
                    if let Some(addr) = listen_handle.listening().await {
                        tracing::info!("server has started {:#?}", addr);
                        tx.send(addr)
                            .expect("failed to send listening notification");
                        break;
                    }
                }
            });
        });

        thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async {
                server.start().await.expect("failed to start server");
            });
        });

        Ok(ShutdownHandle(user_handle))
    }
}

/// Ensure the server is shutdown when the handle is dropped.
pub struct ShutdownHandle(Handle);

impl Drop for ShutdownHandle {
    fn drop(&mut self) {
        tracing::info!("shutdown mock server");
        self.0.shutdown();
    }
}

pub fn spawn() -> Result<(oneshot::Receiver<SocketAddr>, ShutdownHandle)> {
    let (tx, rx) = oneshot::channel::<SocketAddr>();
    let handle = MockServer::spawn(tx)?;
    Ok((rx, handle))
}

pub fn server() -> Url {
    Url::parse(SERVER).expect("failed to parse server URL")
}

#[derive(Debug)]
pub struct TestDirs {
    pub target: PathBuf,
    pub server: PathBuf,
    pub clients: Vec<PathBuf>,
}

pub async fn setup(num_clients: usize) -> Result<TestDirs> {
    let current_dir = std::env::current_dir()
        .expect("failed to get current working directory");
    let target = current_dir.join("target/integration-test");
    vfs::create_dir_all(&target).await?;

    let server = target.join("server");
    let _ = vfs::remove_dir_all(&server).await;

    // Setup required sub-directories
    vfs::create_dir(&server).await?;

    let mut clients = Vec::new();
    for index in 0..num_clients {
        let client = target.join(&format!("client{}", index + 1));
        let _ = vfs::remove_dir_all(&client).await;
        vfs::create_dir(&client).await?;
        clients.push(client);
    }

    Ok(TestDirs {
        target,
        server,
        clients,
    })
}

pub fn mock_note(label: &str, text: &str) -> (SecretMeta, Secret) {
    let secret_value = Secret::Note {
        text: secrecy::Secret::new(text.to_string()),
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    (secret_meta, secret_value)
}

pub async fn create_secrets(
    provider: &mut RemoteProvider,
    summary: &Summary,
) -> Result<Vec<(SecretId, &'static str)>> {
    let notes = vec![
        ("note1", "secret1"),
        ("note2", "secret2"),
        ("note3", "secret3"),
    ];

    let keeper = provider.current_mut().unwrap();

    let mut results = Vec::new();

    // Create some notes locally and get the events
    // to send in a patch.
    let mut create_events = Vec::new();
    for item in notes.iter() {
        let (meta, secret) = mock_note(item.0, item.1);
        let event = keeper.create(meta, secret).await?;

        let id = if let WriteEvent::CreateSecret(secret_id, _) = &event {
            *secret_id
        } else {
            unreachable!()
        };

        let event = event.into_owned();
        create_events.push(event);

        results.push((id, item.0));
    }

    assert_eq!(3, keeper.vault().len());

    // Send the patch to the remote server
    provider.patch(summary, create_events).await?;

    Ok(results)
}

pub async fn delete_secret(
    provider: &mut RemoteProvider,
    summary: &Summary,
    id: &SecretId,
) -> Result<()> {
    let keeper = provider.current_mut().unwrap();
    let event = keeper.delete(id).await?.unwrap();
    let event = event.into_owned();

    // Send the patch to the remote server
    provider.patch(summary, vec![event]).await?;
    Ok(())
}
