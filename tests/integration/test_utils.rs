use anyhow::{bail, Result};
use axum_server::Handle;

use secrecy::SecretString;
use std::{
    net::SocketAddr, path::PathBuf, sync::Arc, thread, time::Duration,
};
use tokio::sync::{oneshot, RwLock};
use url::Url;
use web3_address::ethereum::Address;

use sos_net::{
    client::{Origin, RemoteBridge, RemoteSync, UserStorage},
    sdk::{
        account::{ImportedAccount, LocalProvider},
        crypto::AccessKey,
        events::{AuditLogFile, WriteEvent},
        hex,
        mpc::{Keypair, PATTERN},
        passwd::diceware::generate_passphrase,
        signer::ecdsa::{BoxedEcdsaSigner, SingleParty},
        vault::{
            secret::{Secret, SecretId, SecretMeta},
            Summary,
        },
        vfs,
    },
    server::{
        BackendHandler, Server, ServerConfig, ServerInfo, State,
        TransportManager,
    },
    FileLocks,
};

const ADDR: &str = "127.0.0.1:0";
const SERVER_PUBLIC_KEY: &str = include_str!("../server_public_key.txt");

#[allow(dead_code)]
pub fn init_tracing() {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    let _ = tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| {
                "integration=debug,sos_net=debug,sos_sdk=debug".into()
            }),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .try_init();
}

/// Pause a while to allow synchronization.
///
/// Declared here as we may need to adjust for CI.
pub async fn sync_pause() {
    tokio::time::sleep(Duration::from_millis(50)).await;
}

/// Create a remote provider for the given signing key.
async fn remote_bridge(
    origin: &Origin,
    signer: BoxedEcdsaSigner,
    data_dir: Option<PathBuf>,
) -> Result<RemoteBridge> {
    let keypair = Keypair::new(PATTERN.parse()?)?;
    let local =
        LocalProvider::new(signer.address()?.to_string(), data_dir).await?;
    let provider = RemoteBridge::new(
        Arc::new(RwLock::new(local)),
        origin.clone(),
        signer,
        keypair,
    )?;

    // Noise protocol handshake
    provider.handshake().await?;

    Ok(provider)
}

/// Read the test server public key.
pub fn server_public_key() -> Vec<u8> {
    hex::decode(SERVER_PUBLIC_KEY).unwrap()
}

/// Encapsulates the credentials for a new account signup.
pub struct AccountCredentials {
    /// Passphrase for the vault encryption.
    pub encryption_passphrase: AccessKey,
    /// Address of the signing key.
    pub address: Address,
    /// Summary that represents the login vault
    /// created when the account was created.
    pub summary: Summary,
}

/// Convert a socket address to a URL.
fn socket_addr_url(addr: &SocketAddr) -> Url {
    let server = format!("http://{}:{}", addr.ip(), addr.port());
    Url::parse(&server).expect("failed to parse server URL from socket addr")
}

struct MockServer {
    handle: Handle,
    addr: SocketAddr,
}

impl MockServer {
    fn new(addr: Option<SocketAddr>) -> Result<Self> {
        let default_addr: SocketAddr = ADDR.parse::<SocketAddr>()?;
        Ok(Self {
            handle: Handle::new(),
            addr: addr.unwrap_or(default_addr),
        })
    }

    async fn start(&self) -> Result<()> {
        tracing::info!("start mock server {:#?}", self.addr);

        let (config, keypair) =
            ServerConfig::load("tests/config.toml").await?;

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
                public_key: keypair.public_key().to_owned(),
            },
            keypair,
            config,
            audit_log,
            sockets: Default::default(),
            transports: TransportManager::new(3000),
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
    fn spawn(
        addr: Option<SocketAddr>,
        tx: oneshot::Sender<SocketAddr>,
    ) -> Result<ShutdownHandle> {
        let server = MockServer::new(addr)?;
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

pub struct TestServer {
    pub addr: SocketAddr,
    pub url: Url,
    pub handle: ShutdownHandle,
    pub origin: Origin,
}

pub async fn spawn(
    addr: Option<SocketAddr>,
) -> Result<TestServer> {
    let (tx, rx) = oneshot::channel::<SocketAddr>();
    let handle = MockServer::spawn(addr, tx)?;
    let addr = rx.await?;
    let url = socket_addr_url(&addr);
    Ok(TestServer {
        origin: Origin {
            name: "origin".to_owned(),
            url: url.clone(),
            public_key: server_public_key(),
        },
        addr,
        url,
        handle,
    })
}

#[derive(Debug)]
pub struct TestDirs {
    pub target: PathBuf,
    pub server: PathBuf,
    pub clients: Vec<PathBuf>,
}

/// Setup prepares directories for the given number of clients and
/// a standard location for a remote server storage location.
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

pub async fn create_local_account(
    account_name: &str,
    data_dir: Option<PathBuf>,
) -> Result<(UserStorage, ImportedAccount, Summary, SecretString)> {
    let (passphrase, _) = generate_passphrase()?;
    let (mut owner, imported_account, _) =
        UserStorage::new_account_with_builder(
            account_name.to_owned(),
            passphrase.clone(),
            |builder| {
                builder
                    .save_passphrase(false)
                    .create_archive(true)
                    .create_authenticator(false)
                    .create_contacts(true)
                    .create_file_password(true)
            },
            None,
            data_dir,
        )
        .await?;

    let ImportedAccount { summary, .. } = &imported_account;

    owner.initialize_search_index().await?;

    let summary = summary.to_owned();
    Ok((owner, imported_account, summary, passphrase))
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
    provider: &mut LocalProvider,
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

    // Applt the patch of events
    provider.patch(summary, create_events).await?;

    Ok(results)
}

pub async fn delete_secret(
    provider: &mut LocalProvider,
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

/*
async fn create_account(
    server: Url,
    destination: PathBuf,
    name: Option<String>,
    signer: BoxedEcdsaSigner,
    data_dir: PathBuf,
) -> Result<(AccountCredentials, RemoteBridge)> {
    if !vfs::metadata(&destination).await?.is_dir() {
        bail!("not a directory {}", destination.display());
    }

    let address = signer.address()?;
    let (_origin, provider) = remote_bridge(signer, Some(data_dir)).await?;

    let local_provider = provider.local();
    let mut local_writer = local_provider.write().await;

    let (_, encryption_passphrase, summary) =
        local_writer.create_account(name, None).await?;

    let account = AccountCredentials {
        encryption_passphrase,
        address,
        summary,
    };

    Ok((account, provider))
}
*/

/// Create a new account and local provider.
pub async fn create_local_provider(
    signer: BoxedEcdsaSigner,
    data_dir: Option<PathBuf>,
) -> Result<(AccountCredentials, LocalProvider)> {
    let address = signer.address()?;
    let mut provider =
        LocalProvider::new(address.to_string(), data_dir).await?;
    let (_, encryption_passphrase, summary) =
        provider.create_account(None, None).await?;
    let account = AccountCredentials {
        encryption_passphrase,
        address,
        summary,
    };
    Ok((account, provider))
}

pub async fn signup(
    data_dir: PathBuf,
    origin: &Origin,
) -> Result<(Address, AccountCredentials, RemoteBridge, BoxedEcdsaSigner)> {
    let signer: BoxedEcdsaSigner = Box::new(SingleParty::new_random());

    let address = signer.address()?;
    let provider =
        remote_bridge(origin, signer.clone(), Some(data_dir)).await?;

    let local_provider = provider.local();
    let mut local_writer = local_provider.write().await;

    let (_, encryption_passphrase, summary) =
        local_writer.create_account(None, None).await?;

    let credentials = AccountCredentials {
        encryption_passphrase,
        address,
        summary,
    };

    drop(local_writer);

    provider.sync().await?;

    Ok((address, credentials, provider, signer))
}
