use sos_core::signer::SingleParty;
use sos_readline::read_password;
use std::{fs::File, future::Future, io::Read, path::PathBuf, sync::Arc};
use tokio::runtime::Runtime;
use url::Url;
use web3_keystore::{decrypt, KeyStore};

mod client;
mod error;
mod monitor;
mod shell;
mod signup;

pub type Result<T> = std::result::Result<T, error::Error>;

/// Runs a future blocking the current thread so we can
/// merge the synchronous nature of the shell prompt with the
/// asynchronous API exposed by the client.
pub(crate) fn run_blocking<F, R>(func: F) -> Result<R>
where
    F: Future<Output = Result<R>> + Send,
    R: Send,
{
    Ok(Runtime::new().unwrap().block_on(func)?)
}

pub(crate) fn display_passphrase(
    heading: &str,
    detail: &str,
    passphrase: &str,
) {
    println!("### {}", heading);
    println!("#");
    println!("# {}", detail);
    println!("#");
    println!("# {}", passphrase);
    println!("#");
    println!("###");
}

pub struct ClientBuilder {
    server: Url,
    keystore: PathBuf,
}

impl ClientBuilder {
    pub fn new(server: Url, keystore: PathBuf) -> Self {
        Self { server, keystore }
    }

    pub fn build(self) -> Result<Client> {
        // Decrypt the keystore and create the client.
        let mut keystore_file = File::open(&self.keystore)?;
        let mut keystore_bytes = Vec::new();
        keystore_file.read_to_end(&mut keystore_bytes)?;
        let keystore: KeyStore = serde_json::from_slice(&keystore_bytes)?;

        let password = read_password(Some("Passphrase: "))?;
        let signing_bytes = decrypt(&keystore, &password)?;

        let signing_key: [u8; 32] = signing_bytes.as_slice().try_into()?;
        let signer: SingleParty = (&signing_key).try_into()?;
        Ok(Client::new(self.server, Arc::new(signer)))
    }
}

pub use client::{Client, VaultInfo};
pub use error::Error;
pub use monitor::monitor;
pub use shell::{exec, list_vaults, ShellState};
pub use signup::signup;
