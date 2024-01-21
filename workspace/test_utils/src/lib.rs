//! Test utilities.
#![deny(missing_docs)]
#![forbid(unsafe_code)]

use anyhow::Result;
use axum_server::Handle;
use copy_dir::copy_dir;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::Duration,
};
use tokio::sync::{oneshot, RwLock};

use sos_net::{
    sdk::{signer::ecdsa::Address, sync::Origin, url::Url, vfs, Paths},
    server::{Server, ServerConfig, State},
};

pub mod mock;
mod network;
pub use network::*;

const ADDR: &str = "127.0.0.1:0";

/// Initialize a tracing subscriber.
#[allow(dead_code)]
pub fn init_tracing() {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    let _ = tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "debug,hyper=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .try_init();
}

/// Pause a while to allow synchronization.
///
/// Declared here as we may need to adjust for CI.
pub async fn sync_pause(millis: Option<u64>) {
    tokio::time::sleep(Duration::from_millis(millis.unwrap_or(250))).await;
}

/// Load the default test server config.
pub async fn default_server_config() -> Result<ServerConfig> {
    Ok(ServerConfig::load("tests/config.toml").await?)
}

/// Convert a socket address to a URL.
fn socket_addr_url(addr: &SocketAddr) -> Url {
    let server = format!("http://{}:{}", addr.ip(), addr.port());
    Url::parse(&server).expect("failed to parse server URL from socket addr")
}

struct MockServer {
    handle: Handle,
    addr: SocketAddr,
    path: PathBuf,
}

impl MockServer {
    fn new(addr: Option<SocketAddr>, path: PathBuf) -> Result<Self> {
        let default_addr: SocketAddr = ADDR.parse::<SocketAddr>()?;
        Ok(Self {
            handle: Handle::new(),
            addr: addr.unwrap_or(default_addr),
            path,
        })
    }

    async fn start(&self, config: Option<ServerConfig>) -> Result<()> {
        tracing::info!(
            addr = ?self.addr,
            path = ?self.path,
            "start mock server");

        let mut config = if let Some(config) = config {
            config
        } else {
            default_server_config().await?
        };

        // Override the storage path to use the path
        // using the test identifier
        config.storage.path = self.path.clone();

        let backend = config.backend().await?;
        let state = Arc::new(RwLock::new(State {
            config,
            sockets: Default::default(),
        }));

        let server = Server::new();
        server
            .start(
                self.addr.clone(),
                state,
                Arc::new(RwLock::new(backend)),
                self.handle.clone(),
            )
            .await?;
        Ok(())
    }

    /// Run the mock server in a separate thread.
    fn launch(
        addr: Option<SocketAddr>,
        path: PathBuf,
        tx: oneshot::Sender<SocketAddr>,
        config: Option<ServerConfig>,
    ) -> Result<ShutdownHandle> {
        let server = MockServer::new(addr, path)?;
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
                server.start(config).await.expect("failed to start server");
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

/// Test server information.
pub struct TestServer {
    /// Test identifier.
    pub test_id: String,
    /// Path to the server storage.
    pub path: PathBuf,
    /// Bind address.
    pub addr: SocketAddr,
    /// Handle when dropped will shutdown the server.
    #[allow(dead_code)]
    handle: ShutdownHandle,
    /// Origin for remote connections.
    pub origin: Origin,
}

impl TestServer {
    /// Server paths for the given address.
    pub fn paths(&self, address: &Address) -> Arc<Paths> {
        Arc::new(Paths::new_server(self.path.clone(), address.to_string()))
    }

    /// Path to the server account data.
    pub fn account_path(&self, address: &Address) -> PathBuf {
        let paths = self.paths(address);
        paths.user_dir().to_owned()
    }
}

/// Spawn a mock server and wait for it to be listening
/// using the default test config.
pub async fn spawn(
    test_id: &str,
    addr: Option<SocketAddr>,
    server_id: Option<&str>,
) -> Result<TestServer> {
    spawn_with_config(test_id, addr, server_id, None).await
}

/// Spawn a mock server using the given config.
pub async fn spawn_with_config(
    test_id: &str,
    addr: Option<SocketAddr>,
    server_id: Option<&str>,
    config: Option<ServerConfig>,
) -> Result<TestServer> {
    let current_dir = std::env::current_dir()
        .expect("failed to get current working directory");

    // Prepare server storage
    let target = current_dir.join("target/integration-test");
    vfs::create_dir_all(&target).await?;

    let server_id = server_id.unwrap_or("server");

    // Ensure test runner is pristine
    let path = target.join(test_id).join(server_id);

    // Some tests need to restart a server so we should
    // not wipe out the data (eg: sync offline manual)
    if addr.is_none() {
        let _ = vfs::remove_dir_all(&path).await;
    }

    // Setup required sub-directories
    vfs::create_dir_all(&path).await?;

    let (tx, rx) = oneshot::channel::<SocketAddr>();
    let handle = MockServer::launch(addr, path.clone(), tx, config)?;
    let addr = rx.await?;
    let url = socket_addr_url(&addr);
    Ok(TestServer {
        test_id: test_id.to_owned(),
        path,
        origin: url.into(),
        addr,
        handle,
    })
}

/// Test directory information.
#[derive(Debug, Clone)]
pub struct TestDirs {
    /// Target directory.
    pub target: PathBuf,
    /// Directory for each created client (local account).
    pub clients: Vec<PathBuf>,
}

/// Setup prepares directories for the given number of clients.
pub async fn setup(test_id: &str, num_clients: usize) -> Result<TestDirs> {
    let current_dir = std::env::current_dir()
        .expect("failed to get current working directory");
    let target = current_dir.join("target/integration-test");
    vfs::create_dir_all(&target).await?;

    let mut clients = Vec::new();
    for index in 0..num_clients {
        let client =
            target.join(test_id).join(&format!("client{}", index + 1));
        let _ = vfs::remove_dir_all(&client).await;
        vfs::create_dir_all(&client).await?;
        clients.push(client);
    }

    Ok(TestDirs { target, clients })
}

/// Copy account files removing the target directory first.
pub fn copy_account(
    source: impl AsRef<Path>,
    target: impl AsRef<Path>,
) -> Result<()> {
    std::fs::remove_dir(target.as_ref())?;
    copy_dir(source.as_ref(), target.as_ref())?;
    Ok(())
}

/// Clean up test resources on disc.
pub async fn teardown(test_id: &str) {
    let current_dir = std::env::current_dir()
        .expect("failed to get current working directory");
    let target = current_dir.join("target/integration-test").join(test_id);
    tracing::debug!(path = ?target, "teardown");
    if let Err(e) = vfs::remove_dir_all(&target).await {
        // Sometimes we get this:
        //
        // Os { code: 66, kind: DirectoryNotEmpty, message: "Directory not empty" }
        //
        // Typically this is caused by a test not signing out before
        // calling teardown() and the file transfers background task
        // writing the transfers queue whilst we are in the process of
        // deleting the directory.
        eprintln!("teardown error {} {:#?}", test_id, e);
    }
    /*
    let _ = tracing::subscriber::set_global_default(
        tracing::subscriber::NoSubscriber::new(),
    );
    */
}
