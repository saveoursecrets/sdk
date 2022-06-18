//! HTTP client implementation.
//use std::{path::PathBuf, fs::File, io::Read};
use reqwest::Client as HttpClient;
use sos_core::{signer::Signer, vault::Summary};
use std::sync::Arc;
use url::Url;

use crate::Result;

pub struct Client {
    api: Url,
    http_client: HttpClient,
    signer: Arc<dyn Signer + Send + Sync>,
}

impl Client {
    /// Create a new client.
    pub fn new(api: Url, signer: Arc<dyn Signer + Send + Sync>) -> Self {
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
    pub async fn login(&self) -> Result<Vec<Summary>> {
        println!("Do the login stuff...");
        Ok(vec![])
    }
}
