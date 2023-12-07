use anyhow::Result;
use axum_server::Handle;

use secrecy::SecretString;
use std::{
    net::SocketAddr, path::PathBuf, sync::Arc, thread, time::Duration,
};
use tokio::sync::{oneshot, RwLock};
use url::Url;
use web3_address::ethereum::Address;

use sos_net::{
    client::{HostedOrigin, NetworkAccount, RemoteBridge, RemoteSync},
    mpc::{Keypair, PATTERN},
    sdk::{
        crypto::AccessKey,
        hex,
        passwd::diceware::generate_passphrase,
        signer::ecdsa::{BoxedEcdsaSigner, SingleParty},
        storage::FolderStorage,
        vault::{secret::SecretId, Summary},
        vfs, Paths,
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
    tokio::time::sleep(Duration::from_millis(200)).await;
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

    async fn start(&self) -> Result<()> {
        tracing::info!(
            addr = ?self.addr,
            path = ?self.path,
            "start mock server");

        let (mut config, keypair) =
            ServerConfig::load("tests/config.toml").await?;

        // Override the storage path to use the path
        // using the test identifier
        config.storage.url =
            Url::parse(&format!("file://{}", self.path.display()))?;

        let mut backend = config.backend().await?;

        let state = Arc::new(RwLock::new(State {
            info: ServerInfo {
                name: String::from("integration-test"),
                version: String::from("0.0.0"),
                public_key: keypair.public_key().to_owned(),
            },
            keypair,
            config,
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
    fn launch(
        addr: Option<SocketAddr>,
        path: PathBuf,
        tx: oneshot::Sender<SocketAddr>,
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

/// Test server information.
pub struct TestServer {
    /// Test identifier.
    pub test_id: String,
    /// Path to the server storage.
    pub path: PathBuf,
    /// Bind address.
    pub addr: SocketAddr,
    /// URL for clients to connect to.
    pub url: Url,
    /// Handle when dropped will shutdown the server.
    #[allow(dead_code)]
    handle: ShutdownHandle,
    /// Origin for remote connections.
    pub origin: HostedOrigin,
}

impl TestServer {
    /// Path to the server account data.
    pub fn account_path(&self, address: &Address) -> PathBuf {
        let paths = Paths::new_server(self.path.clone(), address.to_string());
        paths.user_dir().to_owned()
    }
}

/// Spawn a mock server and wait for it to be listening
/// then return test server information.
pub async fn spawn(
    test_id: &str,
    addr: Option<SocketAddr>,
    server_id: Option<&str>,
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
    let handle = MockServer::launch(addr, path.clone(), tx)?;
    let addr = rx.await?;
    let url = socket_addr_url(&addr);
    Ok(TestServer {
        test_id: test_id.to_owned(),
        path,
        origin: HostedOrigin {
            name: "origin".to_owned(),
            url: url.clone(),
            public_key: hex::decode(SERVER_PUBLIC_KEY)?,
        },
        addr,
        url,
        handle,
    })
}

#[derive(Debug, Clone)]
pub struct TestDirs {
    pub target: PathBuf,
    pub clients: Vec<PathBuf>,
}

/// Setup prepares directories for the given number of clients.
pub async fn setup(test_id: &str, num_clients: usize) -> Result<TestDirs> {
    Paths::reset_audit_log();

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

/*
pub async fn delete_secret(
    provider: &mut FolderStorage,
    summary: &Summary,
    id: &SecretId,
) -> Result<()> {
    let keeper = provider.current_mut().unwrap();
    let event = keeper.delete(id).await?.unwrap();
    // Send the patch to the remote server
    provider.patch(summary, vec![&event]).await?;
    Ok(())
}
*/

/// Clean up test resources on disc.
pub async fn teardown(test_id: &str) {
    let current_dir = std::env::current_dir()
        .expect("failed to get current working directory");
    let target = current_dir.join("target/integration-test").join(test_id);
    tracing::debug!(path = ?target, "teardown");
    vfs::remove_dir_all(&target)
        .await
        .expect("to remove test directory");
    /*
    let _ = tracing::subscriber::set_global_default(
        tracing::subscriber::NoSubscriber::new(),
    );
    */
}

pub mod mock {
    use anyhow::Result;
    use secrecy::SecretString;
    use sha2::{Digest, Sha256};
    use sos_net::sdk::{
        age,
        device::TrustedDevice,
        pem,
        vault::secret::{FileContent, IdentityKind, Secret, SecretMeta},
    };
    use std::collections::HashMap;
    use std::path::PathBuf;

    const IPHONE: &str = include_str!("../fixtures/devices/iphone.json");

    pub fn login(
        label: &str,
        account: &str,
        password: SecretString,
    ) -> (SecretMeta, Secret) {
        let secret_value = Secret::Account {
            account: account.to_owned(),
            password,
            url: None,
            user_data: Default::default(),
        };
        let secret_meta =
            SecretMeta::new(label.to_string(), secret_value.kind());
        (secret_meta, secret_value)
    }

    pub fn note(label: &str, text: &str) -> (SecretMeta, Secret) {
        let secret_value = Secret::Note {
            text: secrecy::Secret::new(text.to_string()),
            user_data: Default::default(),
        };
        let secret_meta =
            SecretMeta::new(label.to_string(), secret_value.kind());
        (secret_meta, secret_value)
    }

    pub fn card(
        label: &str,
        number: &str,
        cvv: &str,
    ) -> (SecretMeta, Secret) {
        let secret_value = Secret::Card {
            number: secrecy::Secret::new(number.to_string()),
            cvv: secrecy::Secret::new(cvv.to_string()),
            expiry: None,
            name: None,
            atm_pin: None,
            user_data: Default::default(),
        };
        let secret_meta =
            SecretMeta::new(label.to_string(), secret_value.kind());
        (secret_meta, secret_value)
    }

    pub fn bank(
        label: &str,
        number: &str,
        routing: &str,
    ) -> (SecretMeta, Secret) {
        let secret_value = Secret::Bank {
            number: secrecy::Secret::new(number.to_string()),
            routing: secrecy::Secret::new(routing.to_string()),
            iban: None,
            swift: None,
            bic: None,
            user_data: Default::default(),
        };
        let secret_meta =
            SecretMeta::new(label.to_string(), secret_value.kind());
        (secret_meta, secret_value)
    }

    pub fn list(
        label: &str,
        items: HashMap<&str, &str>,
    ) -> (SecretMeta, Secret) {
        let secret_value = Secret::List {
            items: items
                .into_iter()
                .map(|(k, v)| {
                    (k.to_owned(), secrecy::Secret::new(v.to_owned()))
                })
                .collect(),
            user_data: Default::default(),
        };
        let secret_meta =
            SecretMeta::new(label.to_string(), secret_value.kind());
        (secret_meta, secret_value)
    }

    pub fn pem(label: &str) -> (SecretMeta, Secret) {
        const CERTIFICATE: &str =
            include_str!("../../tests/fixtures/mock-cert.pem");
        let certificates = pem::parse_many(CERTIFICATE).unwrap();
        let secret_value = Secret::Pem {
            certificates,
            user_data: Default::default(),
        };
        let secret_meta =
            SecretMeta::new(label.to_string(), secret_value.kind());
        (secret_meta, secret_value)
    }

    pub fn internal_file(
        label: &str,
        name: &str,
        mime: &str,
        buffer: impl AsRef<[u8]>,
    ) -> (SecretMeta, Secret) {
        let checksum = Sha256::digest(&buffer);
        let secret_value = Secret::File {
            content: FileContent::Embedded {
                name: name.to_string(),
                mime: mime.to_string(),
                checksum: checksum.try_into().unwrap(),
                buffer: secrecy::Secret::new(buffer.as_ref().to_owned()),
            },
            user_data: Default::default(),
        };
        let secret_meta =
            SecretMeta::new(label.to_string(), secret_value.kind());
        (secret_meta, secret_value)
    }

    pub fn link(label: &str, url: &str) -> (SecretMeta, Secret) {
        let secret_value = Secret::Link {
            url: SecretString::new(url.to_string()),
            label: None,
            title: None,
            user_data: Default::default(),
        };
        let secret_meta =
            SecretMeta::new(label.to_string(), secret_value.kind());
        (secret_meta, secret_value)
    }

    pub fn password(
        label: &str,
        password: SecretString,
    ) -> (SecretMeta, Secret) {
        let secret_value = Secret::Password {
            password,
            name: None,
            user_data: Default::default(),
        };
        let secret_meta =
            SecretMeta::new(label.to_string(), secret_value.kind());
        (secret_meta, secret_value)
    }

    pub fn age(label: &str) -> (SecretMeta, Secret) {
        let secret_value = Secret::Age {
            version: Default::default(),
            key: age::x25519::Identity::generate().to_string(),
            user_data: Default::default(),
        };
        let secret_meta =
            SecretMeta::new(label.to_string(), secret_value.kind());
        (secret_meta, secret_value)
    }

    pub fn identity(
        label: &str,
        id_kind: IdentityKind,
        number: &str,
    ) -> (SecretMeta, Secret) {
        let secret_value = Secret::Identity {
            id_kind,
            number: SecretString::new(number.to_string()),
            issue_place: None,
            issue_date: None,
            expiry_date: None,
            user_data: Default::default(),
        };
        let secret_meta =
            SecretMeta::new(label.to_string(), secret_value.kind());
        (secret_meta, secret_value)
    }

    pub fn totp(label: &str) -> (SecretMeta, Secret) {
        use sos_net::sdk::totp::{Algorithm, TOTP};
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            "MockSecretWhichMustBeAtLeast80Bytes".as_bytes().to_vec(),
            Some("MockIssuer".to_string()),
            "mock@example.com".to_string(),
        )
        .unwrap();

        let secret_value = Secret::Totp {
            totp,
            user_data: Default::default(),
        };
        let secret_meta =
            SecretMeta::new(label.to_string(), secret_value.kind());
        (secret_meta, secret_value)
    }

    pub fn contact(label: &str, full_name: &str) -> (SecretMeta, Secret) {
        use sos_net::sdk::vcard4::Vcard;
        let text = format!(
            r#"BEGIN:VCARD
VERSION:4.0
FN:{}
END:VCARD"#,
            full_name
        );
        let vcard: Vcard = text.as_str().try_into().unwrap();
        let secret_value = Secret::Contact {
            vcard: Box::new(vcard),
            user_data: Default::default(),
        };
        let secret_meta =
            SecretMeta::new(label.to_string(), secret_value.kind());
        (secret_meta, secret_value)
    }

    pub fn page(
        label: &str,
        title: &str,
        document: &str,
    ) -> (SecretMeta, Secret) {
        let secret_value = Secret::Page {
            title: title.to_string(),
            mime: "text/markdown".to_string(),
            document: secrecy::Secret::new(document.to_string()),
            user_data: Default::default(),
        };
        let secret_meta =
            SecretMeta::new(label.to_string(), secret_value.kind());
        (secret_meta, secret_value)
    }

    pub fn file_image_secret() -> Result<(SecretMeta, Secret, PathBuf)> {
        let file_path = PathBuf::from("tests/fixtures/sample.heic");
        let secret: Secret = file_path.clone().try_into()?;
        let meta = SecretMeta::new("image".to_string(), secret.kind());
        Ok((meta, secret, file_path))
    }

    pub fn file_text_secret() -> Result<(SecretMeta, Secret, PathBuf)> {
        let file_path = PathBuf::from("tests/fixtures/test-file.txt");
        let secret: Secret = file_path.clone().try_into()?;
        let meta = SecretMeta::new("text".to_string(), secret.kind());
        Ok((meta, secret, file_path))
    }

    pub fn device() -> Result<TrustedDevice> {
        let device: TrustedDevice = serde_json::from_str(IPHONE)?;
        Ok(device)
    }
}

// Backwards compat
#[deprecated]
pub use mock::note as mock_note;
