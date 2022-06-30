//! HTTP client implementation.
use rand::Rng;
use reqwest::{
    header::HeaderMap, Client as HttpClient, RequestBuilder, Response,
};
use reqwest_eventsource::EventSource;
use sos_core::{
    address::AddressStr,
    commit_tree::{decode_proof, encode_proof, CommitProof},
    events::SyncEvent,
    headers::{X_COMMIT_HASH, X_COMMIT_PROOF, X_SIGNED_MESSAGE},
    patch::Patch,
    signer::Signer,
    vault::{encode, Summary, MIME_TYPE_VAULT},
};
use std::sync::Arc;
use url::Url;
use uuid::Uuid;
use web3_signature::Signature;

use crate::{Error, Result};

type Challenge = [u8; 32];

const AUTHORIZATION: &str = "authorization";
const CONTENT_TYPE: &str = "content-type";

fn decode_headers_proof(headers: &HeaderMap) -> Result<Option<CommitProof>> {
    if let (Some(commit_hash), Some(commit_proof)) =
        (headers.get(X_COMMIT_HASH), headers.get(X_COMMIT_PROOF))
    {
        let commit_hash = base64::decode(commit_hash)?;
        let commit_proof = base64::decode(commit_proof)?;
        let commit_hash: [u8; 32] = commit_hash.as_slice().try_into()?;
        let commit_proof = decode_proof(&commit_proof)?;
        Ok(Some(CommitProof(commit_hash, commit_proof)))
    } else {
        Ok(None)
    }
}

fn encode_headers_proof(
    mut builder: RequestBuilder,
    proof: &CommitProof,
) -> RequestBuilder {
    builder = builder.header(X_COMMIT_HASH, base64::encode(&proof.0));
    builder = builder
        .header(X_COMMIT_PROOF, base64::encode(encode_proof(&proof.1)));
    builder
}

/// Encapsulates the information returned
/// by sending a HEAD request for a vault.
pub struct VaultInfo {}

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
        let message: [u8; 32] = rand::thread_rng().gen();
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

    /// Get the WAL bytes for a vault.
    pub async fn get_wal(
        &self,
        vault_id: &Uuid,
        proof: Option<&CommitProof>,
    ) -> Result<(Response, Option<CommitProof>)> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        let (message, signature) = self.self_signed().await?;
        let mut builder = self
            .http_client
            .get(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, base64::encode(&message));

        if let Some(proof) = proof {
            builder = encode_headers_proof(builder, proof);
        }

        let response = builder.send().await?;
        let headers = response.headers();
        let server_proof = decode_headers_proof(headers)?;
        Ok((response, server_proof))
    }

    /// Apply events to the WAL file on a remote server.
    pub async fn patch_wal<'a>(
        &self,
        vault_id: &Uuid,
        proof: &CommitProof,
        events: Vec<SyncEvent<'a>>,
    ) -> Result<(Response, Patch<'a>, Option<CommitProof>)> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        let patch: Patch = events.into();
        let message = encode(&patch)?;

        let signature =
            self.encode_signature(self.signer.sign(&message).await?)?;

        let mut builder = self
            .http_client
            .patch(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature));

        builder = encode_headers_proof(builder, proof);
        builder = builder.body(message);

        let response = builder.send().await?;
        let headers = response.headers();
        let server_proof = decode_headers_proof(headers)?;
        Ok((response, patch, server_proof))
    }

    /// Get the commit proof for a remote WAL file.
    pub async fn head_wal(
        &self,
        vault_id: &Uuid,
    ) -> Result<(Response, CommitProof)> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        let (message, signature) = self.self_signed().await?;
        let response = self
            .http_client
            .head(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, base64::encode(&message))
            .send()
            .await?;
        let headers = response.headers();
        let server_proof =
            decode_headers_proof(headers)?.ok_or(Error::ServerProof)?;
        Ok((response, server_proof))
    }

    /*
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
    */

    /*
    /// Get the name of a vault.
    pub async fn vault_name(&self, vault_id: &Uuid) -> Result<String> {
        let url =
            self.server.join(&format!("api/vaults/{}/name", vault_id))?;
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
        name: &str,
    ) -> Result<Response> {
        let url =
            self.server.join(&format!("api/vaults/{}/name", vault_id))?;
        let (message, signature) = self.self_signed().await?;
        let response = self
            .http_client
            .post(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, base64::encode(&message))
            .header(CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(name)?)
            .send()
            .await?;
        Ok(response)
    }
    */

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

    /*
    /// Create a secret.
    pub async fn create_secret(
        &self,
        vault_id: &Uuid,
        secret_id: &SecretId,
        secret: &VaultCommit,
    ) -> Result<Response> {
        let url = self.server.join(&format!(
            "api/vaults/{}/secrets/{}",
            vault_id, secret_id
        ))?;
        let body = serde_json::to_vec(secret)?;
        let signature =
            self.encode_signature(self.signer.sign(&body).await?)?;
        let response = self
            .http_client
            .put(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .body(body)
            .send()
            .await?;
        Ok(response)
    }

    /// Update a secret.
    pub async fn update_secret(
        &self,
        vault_id: &Uuid,
        secret_id: &SecretId,
        secret: &VaultCommit,
    ) -> Result<Response> {
        let url = self.server.join(&format!(
            "api/vaults/{}/secrets/{}",
            vault_id, secret_id
        ))?;
        let body = serde_json::to_vec(secret)?;
        let signature =
            self.encode_signature(self.signer.sign(&body).await?)?;
        let response = self
            .http_client
            .post(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .body(body)
            .send()
            .await?;
        Ok(response)
    }

    /// Send a read secret event to the server.
    pub async fn read_secret(
        &self,
        vault_id: &Uuid,
        secret_id: &SecretId,
    ) -> Result<Response> {
        let url = self.server.join(&format!(
            "api/vaults/{}/secrets/{}",
            vault_id, secret_id
        ))?;
        let (message, signature) = self.self_signed().await?;
        let response = self
            .http_client
            .get(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, base64::encode(&message))
            .send()
            .await?;
        Ok(response)
    }

    /// Send a delete secret event to the server.
    pub async fn delete_secret(
        &self,
        vault_id: &Uuid,
        secret_id: &SecretId,
    ) -> Result<Vec<u8>> {
        let url = self.server.join(&format!(
            "api/vaults/{}/secrets/{}",
            vault_id, secret_id
        ))?;
        let (message, signature) = self.self_signed().await?;
        let response = self
            .http_client
            .delete(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, base64::encode(&message))
            .send()
            .await?;
        Ok(response.bytes().await?.to_vec())
    }
    */

    /// Get an event source for the changes feed.
    pub async fn changes(&self) -> Result<EventSource> {
        let message: [u8; 32] = rand::thread_rng().gen();
        let token = base64::encode(serde_json::to_vec(
            &self.signer.sign(&message).await?,
        )?);
        let message = hex::encode(&message);
        let mut url = self.server.join("/api/changes")?;
        url.query_pairs_mut()
            .append_pair("message", &message)
            .append_pair("token", &token);
        Ok(EventSource::get(url))
    }
}
