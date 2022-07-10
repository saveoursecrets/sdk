//! HTTP client implementation.
use rand::Rng;
use reqwest::{
    header::HeaderMap, Client as HttpClient,
    ClientBuilder as HttpClientBuilder, RequestBuilder, Response,
};
use reqwest_eventsource::EventSource;
use sos_core::{
    address::AddressStr,
    commit_tree::CommitProof,
    constants::{X_COMMIT_PROOF, X_MATCH_PROOF, X_SIGNED_MESSAGE},
    decode,
    signer::Signer,
    vault::{encode, Summary, MIME_TYPE_VAULT},
    Patch,
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
    if let Some(commit_proof) = headers.get(X_COMMIT_PROOF) {
        let value = base64::decode(commit_proof)?;
        let value: CommitProof = decode(&value)?;
        Ok(Some(value))
    } else {
        Ok(None)
    }
}

pub(crate) fn decode_match_proof(
    headers: &HeaderMap,
) -> Result<Option<CommitProof>> {
    if let Some(commit_proof) = headers.get(X_MATCH_PROOF) {
        let value = base64::decode(commit_proof)?;
        let value: CommitProof = decode(&value)?;
        Ok(Some(value))
    } else {
        Ok(None)
    }
}

fn encode_headers_proof(
    mut builder: RequestBuilder,
    proof: &CommitProof,
) -> Result<RequestBuilder> {
    let value = encode(proof)?;
    builder = builder.header(X_COMMIT_PROOF, base64::encode(&value));
    Ok(builder)
}

pub struct Client {
    server: Url,
    http_client: HttpClient,
    signer: Arc<dyn Signer + Send + Sync>,
}

impl Client {
    /// Create a new client.
    pub fn new(server: Url, signer: Arc<dyn Signer + Send + Sync>) -> Self {
        let mut builder = HttpClientBuilder::new();

        // For integration tests we use a self-signed
        // certificate, so this allows the client to connect
        if cfg!(debug_assertions) {
            builder = builder.danger_accept_invalid_certs(true);
        }

        let http_client =
            builder.build().expect("failed to build HTTP client");

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

    /// List the vaults accessible by this signer.
    pub async fn list_vaults(&self) -> Result<Vec<Summary>> {
        let url = self.server.join("api/auth")?;
        let (message, signature) = self.self_signed().await?;

        let response = self
            .http_client
            .get(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, base64::encode(&message))
            .send()
            .await?;

        response
            .status()
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(response.status().into()))?;

        let challenge: (Uuid, Challenge) = response.json().await?;

        let (uuid, message) = challenge;
        let url = format!("api/auth/{}", uuid);
        let url = self.server.join(&url)?;
        let signature =
            self.encode_signature(self.signer.sign(&message).await?)?;

        let response = self
            .http_client
            .get(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, base64::encode(&message))
            .send()
            .await?;

        response
            .status()
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(response.status().into()))?;

        let summaries: Vec<Summary> = response.json().await?;

        Ok(summaries)
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

    /// Create a new WAL file.
    pub async fn create_wal(
        &self,
        vault: Vec<u8>,
    ) -> Result<(Response, Option<CommitProof>)> {
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
        let headers = response.headers();
        let server_proof = decode_headers_proof(headers)?;
        Ok((response, server_proof))
    }

    /// Update an existing vault.
    pub async fn put_vault(
        &self,
        vault_id: &Uuid,
        vault: Vec<u8>,
    ) -> Result<(Response, Option<CommitProof>)> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
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

        let headers = response.headers();
        let server_proof = decode_headers_proof(headers)?;
        Ok((response, server_proof))
    }

    /// Delete a WAL file.
    pub async fn delete_wal(
        &self,
        vault_id: &Uuid,
    ) -> Result<(Response, Option<CommitProof>)> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        let (message, signature) = self.self_signed().await?;
        let response = self
            .http_client
            .delete(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, base64::encode(&message))
            .send()
            .await?;
        let headers = response.headers();
        let server_proof = decode_headers_proof(headers)?;
        Ok((response, server_proof))
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
            builder = encode_headers_proof(builder, proof)?;
        }

        let response = builder.send().await?;
        let headers = response.headers();
        let server_proof = decode_headers_proof(headers)?;
        Ok((response, server_proof))
    }

    /// Apply events to the WAL file on a remote server.
    pub async fn patch_wal(
        &self,
        vault_id: &Uuid,
        proof: &CommitProof,
        patch: &Patch<'_>,
    ) -> Result<(Response, Option<CommitProof>)> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        //let patch: Patch = events.into();
        let message = encode(&*patch)?;

        let signature =
            self.encode_signature(self.signer.sign(&message).await?)?;

        let mut builder = self
            .http_client
            .patch(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature));

        builder = encode_headers_proof(builder, proof)?;
        builder = builder.body(message);

        let response = builder.send().await?;
        let headers = response.headers();
        let server_proof = decode_headers_proof(headers)?;
        Ok((response, server_proof))
    }

    /// Replace a WAL file.
    pub async fn post_wal(
        &self,
        vault_id: &Uuid,
        proof: &CommitProof,
        body: Vec<u8>,
    ) -> Result<(Response, Option<CommitProof>)> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        let signature =
            self.encode_signature(self.signer.sign(&body).await?)?;
        let mut builder = self
            .http_client
            .post(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .header(CONTENT_TYPE, MIME_TYPE_VAULT)
            .body(body);

        builder = encode_headers_proof(builder, proof)?;

        let response = builder.send().await?;
        let headers = response.headers();
        let server_proof = decode_headers_proof(headers)?;
        Ok((response, server_proof))
    }

    /// Get the commit proof for a remote WAL file.
    pub async fn head_wal(
        &self,
        vault_id: &Uuid,
        proof: Option<&CommitProof>,
    ) -> Result<(Response, CommitProof, Option<CommitProof>)> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        let (message, signature) = self.self_signed().await?;
        let mut builder = self
            .http_client
            .head(url)
            .header(AUTHORIZATION, self.bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, base64::encode(&message));

        if let Some(proof) = proof {
            builder = encode_headers_proof(builder, proof)?;
        }

        let response = builder.send().await?;
        let headers = response.headers();

        let server_proof =
            decode_headers_proof(headers)?.ok_or(Error::ServerProof)?;
        let match_proof = decode_match_proof(headers)?;
        Ok((response, server_proof, match_proof))
    }

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
