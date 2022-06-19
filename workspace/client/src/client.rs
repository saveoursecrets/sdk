//! HTTP client implementation.
use reqwest::Client as HttpClient;
use sos_core::{address::AddressStr, signer::Signer, vault::Summary};
use std::sync::Arc;
use url::Url;
use uuid::Uuid;
use web3_signature::Signature;

use crate::Result;

type Challenge = [u8; 32];

pub struct Client {
    server: Url,
    http_client: HttpClient,
    signer: Arc<dyn Signer + Send + Sync>,
}

impl Client {
    /// Create a new client.
    pub fn new(server: Url, signer: Arc<dyn Signer + Send + Sync>) -> Self {
        let http_client = HttpClient::new();
        Self {
            server,
            http_client,
            signer,
        }
    }

    /// Get the server URL.
    pub fn server(&self) -> &Url {
        &self.server
    }

    /// Compute the address of the current signer.
    pub fn address(&self) -> Result<AddressStr> {
        Ok(self.signer.address()?)
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
        let url = self.server.join("api/auth")?;
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
        let url = self.server.join(&url)?;
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

    /// Load the buffer for a vault.
    pub async fn load_vault(&self, vault_id: &Uuid) -> Result<Vec<u8>> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        let (message, signature) = self.self_signed().await?;
        let response = self
            .http_client
            .get(url)
            .header("authorization", self.bearer_prefix(&signature))
            .header("x-signed-message", base64::encode(&message))
            .send()
            .await?;
        Ok(response.bytes().await?.to_vec())
    }

    /// Send a read secret event to the server.
    pub async fn read_secret(
        &self,
        change_seq: u32,
        vault_id: &Uuid,
        secret_id: &Uuid,
    ) -> Result<Vec<u8>> {
        let url = self
            .server
            .join(&format!("api/vaults/{}/secrets/{}", vault_id, secret_id))?;
        let (message, signature) = self.self_signed().await?;
        let response = self
            .http_client
            .get(url)
            .header("authorization", self.bearer_prefix(&signature))
            .header("x-signed-message", base64::encode(&message))
            .header("x-change-sequence", change_seq.to_string())
            .send()
            .await?;
        Ok(response.bytes().await?.to_vec())
    }
}
