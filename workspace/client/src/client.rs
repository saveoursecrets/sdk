//! HTTP client implementation.
use reqwest::{Client as HttpClient, Response};
use sos_core::{
    address::AddressStr,
    signer::Signer,
    vault::{Summary, MIME_TYPE_VAULT},
};
use std::sync::Arc;
use url::Url;
use uuid::Uuid;
use web3_signature::Signature;

use crate::{Error, Result};

type Challenge = [u8; 32];

const AUTHORIZATION: &str = "authorization";
const CONTENT_TYPE: &str = "content-type";
const X_SIGNED_MESSAGE: &str = "x-signed-message";
const X_CHANGE_SEQUENCE: &str = "x-change-sequence";

/// Encapsulates the information returned
/// by sending a HEAD request for a vault.
pub struct VaultInfo {
    pub change_seq: u32,
}

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

    /// Create a new account.
    pub async fn create_account(&self, vault: Vec<u8>) -> Result<Response> {
        let url = self.server.join("api/accounts")?;
        let signature =
            self.encode_signature(self.signer.sign(&vault).await?)?;
        let response = self
            .http_client
            .put(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .header(CONTENT_TYPE, MIME_TYPE_VAULT)
            .body(vault)
            .send()
            .await?;
        Ok(response)
    }

    /// Create a new vault.
    pub async fn create_vault(&self, vault: Vec<u8>) -> Result<Response> {
        let url = self.server.join("api/vaults")?;
        let signature =
            self.encode_signature(self.signer.sign(&vault).await?)?;
        let response = self
            .http_client
            .put(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .header(CONTENT_TYPE, MIME_TYPE_VAULT)
            .body(vault)
            .send()
            .await?;
        Ok(response)
    }

    /// Get the change sequence for a vault.
    pub async fn head_vault(&self, vault_id: &Uuid) -> Result<VaultInfo> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        let (message, signature) = self.self_signed().await?;
        let response = self
            .http_client
            .head(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, base64::encode(&message))
            .send()
            .await?;
        let change_seq = response
            .headers()
            .get(X_CHANGE_SEQUENCE)
            .ok_or_else(|| Error::ChangeSequenceHeader)?;
        let change_seq: u32 = change_seq.to_str()?.parse()?;
        Ok(VaultInfo { change_seq })
    }

    /// Read the buffer for a vault.
    pub async fn read_vault(&self, vault_id: &Uuid) -> Result<Vec<u8>> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        let (message, signature) = self.self_signed().await?;
        let response = self
            .http_client
            .get(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, base64::encode(&message))
            .send()
            .await?;
        Ok(response.bytes().await?.to_vec())
    }

    // TODO: update vault

    /// Delete a vault.
    pub async fn delete_vault(&self, vault_id: &Uuid) -> Result<Response> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        let (message, signature) = self.self_signed().await?;
        let response = self
            .http_client
            .delete(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, base64::encode(&message))
            .send()
            .await?;
        Ok(response)
    }

    /// Get the name of a vault.
    pub async fn vault_name(&self, vault_id: &Uuid) -> Result<String> {
        let url = self.server.join(&format!("api/vaults/{}/name", vault_id))?;
        let (message, signature) = self.self_signed().await?;
        let response = self
            .http_client
            .get(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, base64::encode(&message))
            .send()
            .await?;

        let name: String = response.json().await?;
        Ok(name)
    }

    /// Set the name of a vault.
    pub async fn set_vault_name(
        &self,
        vault_id: &Uuid,
        change_seq: u32,
        name: &str,
    ) -> Result<Response> {
        let url = self.server.join(&format!("api/vaults/{}/name", vault_id))?;
        let (message, signature) = self.self_signed().await?;
        let response = self
            .http_client
            .post(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, base64::encode(&message))
            .header(X_CHANGE_SEQUENCE, change_seq.to_string())
            .header(CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(name)?)
            .send()
            .await?;
        Ok(response)
    }

    /// List the vaults accessible by this signer.
    pub async fn list_vaults(&self) -> Result<Vec<Summary>> {
        let url = self.server.join("api/auth")?;
        let (message, signature) = self.self_signed().await?;

        let challenge: (Uuid, Challenge) = self
            .http_client
            .get(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, base64::encode(&message))
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
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, base64::encode(&message))
            .send()
            .await?
            .json()
            .await?;

        Ok(summaries)
    }

    /// Send a read secret event to the server.
    pub async fn read_secret(
        &self,
        change_seq: u32,
        vault_id: &Uuid,
        secret_id: &Uuid,
    ) -> Result<Response> {
        let url = self
            .server
            .join(&format!("api/vaults/{}/secrets/{}", vault_id, secret_id))?;
        let (message, signature) = self.self_signed().await?;
        let response = self
            .http_client
            .get(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, base64::encode(&message))
            .header(X_CHANGE_SEQUENCE, change_seq.to_string())
            .send()
            .await?;
        Ok(response)
    }

    /// Send a delete secret event to the server.
    pub async fn delete_secret(
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
            .delete(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, base64::encode(&message))
            .header(X_CHANGE_SEQUENCE, change_seq.to_string())
            .send()
            .await?;
        Ok(response.bytes().await?.to_vec())
    }
}
