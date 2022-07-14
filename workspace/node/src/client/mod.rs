use std::{fs::File, io::Read, path::PathBuf, sync::Arc};
use url::Url;

use http_client::Client;

use sos_core::signer::SingleParty;
use web3_keystore::{decrypt, KeyStore};

use crate::{Error, Result};

pub mod account;
pub mod cache;
pub mod http_client;

/// Trait for implementations that can read a passphrase.
pub trait PassphraseReader {
    /// Error generated attempting to read a passphrase.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Read a passphrase.
    fn read(&self) -> std::result::Result<String, Self::Error>;
}

pub struct ClientBuilder<E> {
    server: Url,
    keystore: PathBuf,
    keystore_passphrase: Option<String>,
    passphrase_reader: Option<Box<dyn PassphraseReader<Error = E>>>,
}

impl<E: std::error::Error + Send + Sync + 'static> ClientBuilder<E> {
    pub fn new(server: Url, keystore: PathBuf) -> Self {
        Self {
            server,
            keystore,
            keystore_passphrase: None,
            passphrase_reader: None,
        }
    }

    pub fn with_keystore_passphrase(mut self, passphrase: String) -> Self {
        self.keystore_passphrase = Some(passphrase);
        self
    }

    pub fn with_passphrase_reader(
        mut self,
        reader: Box<dyn PassphraseReader<Error = E>>,
    ) -> Self {
        self.passphrase_reader = Some(reader);
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
        } else if let Some(reader) = self.passphrase_reader {
            reader.read().map_err(Box::from)?
        } else {
            panic!("client builder requires either a passphrase or passphrase reader");
        };
        let signing_bytes = decrypt(&keystore, &passphrase)?;

        let signing_key: [u8; 32] = signing_bytes.as_slice().try_into()?;
        let signer: SingleParty = (&signing_key).try_into()?;
        Ok(Client::new(self.server, Arc::new(signer)))
    }
}
