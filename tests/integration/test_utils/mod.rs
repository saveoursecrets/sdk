use anyhow::Result;
use axum_server::Handle;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, thread};
use tokio::sync::{oneshot, RwLock};
use url::Url;

use sos_audit::AuditLogFile;
use sos_core::FileLocks;
use sos_server::{Authentication, Server, ServerConfig, ServerInfo, State};

const ADDR: &str = "127.0.0.1:3505";
const SERVER: &str = "https://localhost:3505";

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

        let authentication: Authentication = Default::default();
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
            authentication,
            audit_log,
            sse: Default::default(),
        }));

        Server::start(addr, state, self.handle.clone()).await?;
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
    pub client: PathBuf,
}

pub fn setup() -> Result<TestDirs> {
    let current_dir = std::env::current_dir()
        .expect("failed to get current working directory");
    let target = current_dir.join("target/integration-test");
    if !target.exists() {
        std::fs::create_dir_all(&target)?;
    }

    let client = target.join("client");
    if client.exists() {
        std::fs::remove_dir_all(&client)?;
    }

    let server = target.join("server");
    if server.exists() {
        std::fs::remove_dir_all(&server)?;
    }

    // Setup required sub-directories
    std::fs::create_dir(&server)?;
    std::fs::create_dir(&client)?;

    Ok(TestDirs {
        target,
        server,
        client,
    })
}
