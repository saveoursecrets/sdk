//! HTTP client implementation.
//use std::{path::PathBuf, fs::File, io::Read};
use reqwest::Client as HttpClient;
use sos_core::{signer::Signer, vault::Summary};
use std::sync::Arc;
use url::Url;
use uuid::Uuid;
use web3_signature::Signature;

use crate::Result;

type Challenge = [u8; 32];

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

    fn encode_signature(&self, signature: Signature) -> Result<String> {
        Ok(base64::encode(serde_json::to_string(&signature)?))
    }

    fn bearer_prefix(&self, signature: &str) -> String {
        format!("Bearer {}", signature)
    }

    async fn self_signed(&self) -> Result<(Vec<u8>, String)> {
        let message: [u8; 32] = [0u8; 32];
        let signature =
            self.encode_signature(self.signer.sign(&message).await?)?;
        Ok((message.to_vec(), signature))
    }

    /// List the vaults accessible by this signer.
    pub async fn list_vaults(&self) -> Result<Vec<Summary>> {
        let url = self.api.join("api/auth")?;
        let (message, signature) = self.self_signed().await?;

        let challenge: (Uuid, Challenge) = self
            .http_client
            .get(url)
            .header("authorization", self.bearer_prefix(&signature))
            .header("x-signed-message", base64::encode(&message))
            .send()
            .await?
            .json()
            .await?;

        let (uuid, message) = challenge;
        let url = format!("api/auth/{}", uuid);
        let url = self.api.join(&url)?;
        let signature =
            self.encode_signature(self.signer.sign(&message).await?)?;

        let summaries: Vec<Summary> = self
            .http_client
            .get(url)
            .header("authorization", self.bearer_prefix(&signature))
            .header("x-signed-message", base64::encode(&message))
            .send()
            .await?
            .json()
            .await?;

        Ok(summaries)
    }
}
