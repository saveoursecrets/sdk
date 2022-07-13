use sos_core::signer::SingleParty;
use sos_readline::read_password;
use std::{
    borrow::Cow, fs::File, future::Future, io::Read, path::PathBuf, sync::Arc,
};
use terminal_banner::{Banner, Padding};
use tokio::runtime::Runtime;
use url::Url;
use web3_keystore::{decrypt, KeyStore};

mod account;
mod cache;
mod client;
mod error;
mod monitor;
mod shell;

pub type Result<T> = std::result::Result<T, error::Error>;

/// Runs a future blocking the current thread so we can
/// merge the synchronous nature of the shell prompt with the
/// asynchronous API exposed by the client.
pub fn run_blocking<F, R>(func: F) -> Result<R>
where
    F: Future<Output = Result<R>> + Send,
    R: Send,
{
    Runtime::new().unwrap().block_on(func)
}

pub(crate) fn display_passphrase(heading: &str, passphrase: &str) {
    let banner = Banner::new()
        .padding(Padding::one())
        .text(Cow::from(heading))
        .text(Cow::from(passphrase))
        .render();
    println!("{}", banner);
}

pub struct ClientBuilder {
    server: Url,
    keystore: PathBuf,
    keystore_passphrase: Option<String>,
}

impl ClientBuilder {
    pub fn new(server: Url, keystore: PathBuf) -> Self {
        Self {
            server,
            keystore,
            keystore_passphrase: None,
        }
    }

    pub fn with_keystore_passphrase(mut self, passphrase: String) -> Self {
        self.keystore_passphrase = Some(passphrase);
        self
    }

    /// Build a client implementation wrapping a signing key.
    pub fn build(self) -> Result<Client> {
        if !self.keystore.exists() {
            return Err(Error::NotFile(self.keystore));
        }

        // Decrypt the keystore and create the client.
        let mut keystore_file = File::open(&self.keystore)?;
        let mut keystore_bytes = Vec::new();
        keystore_file.read_to_end(&mut keystore_bytes)?;
        let keystore: KeyStore = serde_json::from_slice(&keystore_bytes)?;

        let passphrase = if let Some(passphrase) = self.keystore_passphrase {
            passphrase
        } else {
            read_password(Some("Passphrase: "))?
        };
        let signing_bytes = decrypt(&keystore, &passphrase)?;

        let signing_key: [u8; 32] = signing_bytes.as_slice().try_into()?;
        let signer: SingleParty = (&signing_key).try_into()?;
        Ok(Client::new(self.server, Arc::new(signer)))
    }
}

pub use account::{
    create_account, create_signing_key, login, signup, ClientCredentials,
    ClientKey,
};
pub use cache::{ClientCache, FileCache, SyncInfo, SyncKind, SyncStatus};
pub use client::Client;
pub use error::Error;
pub use monitor::monitor;
pub use shell::exec;
