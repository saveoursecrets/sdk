use anyhow::Result;
use axum_server::Handle;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, thread};
use tokio::sync::{oneshot, RwLock};
use url::Url;

use sos_core::{
    events::SyncEvent,
    secret::{Secret, SecretId, SecretMeta},
    vault::Summary,
    wal::file::WalFile,
    AuditLogFile, FileLocks, PatchFile,
};

use sos_node::{
    client::node_cache::NodeCache,
    server::{Server, ServerConfig, ServerInfo, State},
    session::SessionManager,
};

const ADDR: &str = "127.0.0.1:3505";
const SERVER: &str = "http://localhost:3505";

mod signup;

pub use signup::signup;

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

        let config = ServerConfig::load("tests/config.toml")?;

        let mut backend = config.backend().await?;

        let mut locks = FileLocks::new();
        let _ = locks.add(config.audit_file())?;
        // Move into the backend so it can manage lock files too
        backend.set_file_locks(locks)?;

        // Set up the audit log
        let audit_log = AuditLogFile::new(config.audit_file())?;

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
            ()
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

pub struct TestDirs {
    pub target: PathBuf,
    pub server: PathBuf,
    pub clients: Vec<PathBuf>,
}

pub fn setup(num_clients: usize) -> Result<TestDirs> {
    let current_dir = std::env::current_dir()
        .expect("failed to get current working directory");
    let target = current_dir.join("target/integration-test");
    if !target.exists() {
        std::fs::create_dir_all(&target)?;
    }

    let server = target.join("server");
    if server.exists() {
        std::fs::remove_dir_all(&server)?;
    }

    // Setup required sub-directories
    std::fs::create_dir(&server)?;

    let mut clients = Vec::new();
    for index in 0..num_clients {
        let client = target.join(&format!("client{}", index + 1));
        if client.exists() {
            std::fs::remove_dir_all(&client)?;
        }
        std::fs::create_dir(&client)?;
        clients.push(client);
    }

    Ok(TestDirs {
        target,
        server,
        clients,
    })
}

pub fn mock_note(label: &str, text: &str) -> (SecretMeta, Secret) {
    let secret_value = Secret::Note(secrecy::Secret::new(text.to_string()));
    let secret_meta = SecretMeta::new(label.to_string(), secret_value.kind());
    (secret_meta, secret_value)
}

pub async fn create_secrets(
    node_cache: &mut NodeCache<WalFile, PatchFile>,
    summary: &Summary,
) -> Result<Vec<(SecretId, &'static str)>> {
    let notes = vec![
        ("note1", "secret1"),
        ("note2", "secret2"),
        ("note3", "secret3"),
    ];

    let keeper = node_cache.current_mut().unwrap();

    let mut results = Vec::new();

    // Create some notes locally and get the events
    // to send in a patch.
    let mut create_events = Vec::new();
    for item in notes.iter() {
        let (meta, secret) = mock_note(item.0, item.1);
        let event = keeper.create(meta, secret)?;

        let id = if let SyncEvent::CreateSecret(secret_id, _) = &event {
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
    node_cache.patch_vault(summary, create_events).await?;

    Ok(results)
}

pub async fn delete_secret(
    node_cache: &mut NodeCache<WalFile, PatchFile>,
    summary: &Summary,
    id: &SecretId,
) -> Result<()> {
    let keeper = node_cache.current_mut().unwrap();
    let event = keeper.delete(id)?.unwrap();
    let event = event.into_owned();

    // Send the patch to the remote server
    node_cache.patch_vault(summary, vec![event]).await?;
    Ok(())
}
