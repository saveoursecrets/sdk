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
    client::{NetworkAccount, Origin, RemoteBridge, RemoteSync},
    sdk::{
        account::FolderStorage,
        crypto::AccessKey,
        events::AuditLogFile,
        hex,
        mpc::{Keypair, PATTERN},
        passwd::diceware::generate_passphrase,
        signer::ecdsa::{BoxedEcdsaSigner, SingleParty},
        vault::{secret::SecretId, Summary},
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
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// Create a remote provider for the given signing key.
async fn remote_bridge(
    origin: &Origin,
    signer: BoxedEcdsaSigner,
    data_dir: Option<PathBuf>,
) -> Result<RemoteBridge> {
    let keypair = Keypair::new(PATTERN.parse()?)?;
    let local =
        FolderStorage::new(signer.address()?.to_string(), data_dir).await?;
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
    pub origin: Origin,
}

impl TestServer {
    /// Path to the server account data.
    pub fn account_path(&self, address: &Address) -> PathBuf {
        PathBuf::from(format!("{}/{}", self.path.display(), address,))
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
        origin: Origin {
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

pub async fn create_local_account(
    account_name: &str,
    data_dir: Option<PathBuf>,
) -> Result<(NetworkAccount, Summary, SecretString)> {
    let (passphrase, _) = generate_passphrase()?;
    let (mut owner, new_account) = NetworkAccount::new_account_with_builder(
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
        data_dir,
        None,
    )
    .await?;

    let summary = new_account.default_folder().clone();

    owner.sign_in(passphrase.clone()).await?;

    owner.initialize_search_index().await?;

    let summary = summary.to_owned();
    Ok((owner, summary, passphrase))
}

pub async fn create_secrets(
    provider: &mut FolderStorage,
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
        let id = SecretId::new_v4();
        let event = keeper.create(id, meta, secret).await?;
        create_events.push(event);
        results.push((id, item.0));
    }

    assert_eq!(3, keeper.vault().len());

    // Applt the patch of events
    provider.patch(summary, create_events).await?;

    Ok(results)
}

pub async fn delete_secret(
    provider: &mut FolderStorage,
    summary: &Summary,
    id: &SecretId,
) -> Result<()> {
    let keeper = provider.current_mut().unwrap();
    let event = keeper.delete(id).await?.unwrap();
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
) -> Result<(AccountCredentials, FolderStorage)> {
    let address = signer.address()?;
    let mut provider =
        FolderStorage::new(address.to_string(), data_dir).await?;
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

    let (encryption_passphrase, summary) = {
        let local_provider = provider.local();
        let mut local_writer = local_provider.write().await;
        let (_, encryption_passphrase, summary) =
            local_writer.create_account(None, None).await?;
        (encryption_passphrase, summary)
    };

    assert!(provider.sync().await.is_none());

    let credentials = AccountCredentials {
        encryption_passphrase,
        address,
        summary,
    };

    Ok((address, credentials, provider, signer))
}

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
        age, pem,
        vault::secret::{FileContent, IdentityKind, Secret, SecretMeta},
    };
    use std::collections::HashMap;
    use std::path::PathBuf;

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
            include_str!("../../workspace/sdk/fixtures/mock-cert.pem");
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
}

// Backwards compat
#[deprecated]
pub use mock::note as mock_note;
