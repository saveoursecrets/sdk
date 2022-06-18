//! HTTP client implementation.
//use std::{path::PathBuf, fs::File, io::Read};
use reqwest::Client as HttpClient;
use url::Url;
use sos_core::signer::Signer;

pub struct Client<'a> {
    api: Url,
    http_client: HttpClient,
    signer: &'a mut dyn Signer,
}

impl<'a> Client<'a> {
    /// Create a new client.
    pub fn new(api: Url, signer: &'a mut impl Signer) -> Self {
        let http_client = HttpClient::new();
        Self {
            api,
            http_client,
            signer,
        }
    }

    /// Get the API URL.
    pub fn api(&self) -> &Url {
        &self.api
    }

    /// Login to the server and retrieve the list of vaults
    /// accessible by this signer.
    pub async fn login(&self) {
        todo!("login to server");
    }
}
