//! HTTP client implementation.
use async_trait::async_trait;
use http::StatusCode;
use rand::Rng;
use reqwest::{header::HeaderMap, RequestBuilder, Response};

use reqwest_eventsource::EventSource;
use sos_core::{
    address::AddressStr,
    commit_tree::CommitProof,
    constants::{
        MIME_TYPE_VAULT, X_COMMIT_PROOF, X_MATCH_PROOF, X_SIGNED_MESSAGE,
    },
    decode, encode,
    signer::Signer,
    vault::Summary,
    Patch,
};
use std::sync::Arc;
use url::Url;
use uuid::Uuid;

use crate::client::{Error, Result};

use super::{
    bearer_prefix, changes::ChangeStream, encode_signature, Challenge,
    NetworkClient,
};

const AUTHORIZATION: &str = "authorization";
const CONTENT_TYPE: &str = "content-type";

fn decode_headers_proof(headers: &HeaderMap) -> Result<Option<CommitProof>> {
    if let Some(commit_proof) = headers.get(X_COMMIT_PROOF) {
        let value = bs58::decode(commit_proof).into_vec()?;
        let value: CommitProof = decode(&value)?;
        Ok(Some(value))
    } else {
        Ok(None)
    }
}

fn decode_match_proof(headers: &HeaderMap) -> Result<Option<CommitProof>> {
    if let Some(commit_proof) = headers.get(X_MATCH_PROOF) {
        let value = bs58::decode(commit_proof).into_vec()?;
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
    builder =
        builder.header(X_COMMIT_PROOF, bs58::encode(&value).into_string());
    Ok(builder)
}

/// HTTP client implementation using the `reqwest` library.
pub struct RequestClient {
    server: Url,
    http_client: reqwest::Client,
    signer: Arc<dyn Signer + Send + Sync>,
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl NetworkClient for RequestClient {
    fn address(&self) -> Result<AddressStr> {
        Ok(self.signer.address()?)
    }

    async fn create_account(&self, vault: Vec<u8>) -> Result<StatusCode> {
        let url = self.server.join("api/accounts")?;
        let signature = encode_signature(self.signer.sign(&vault).await?)?;

        let response = self
            .http_client
            .put(url)
            .header(AUTHORIZATION, bearer_prefix(&signature))
            .header(CONTENT_TYPE, MIME_TYPE_VAULT)
            .body(vault)
            .send()
            .await?;

        Ok(StatusCode::from_u16(response.status().into())?)
    }

    async fn list_vaults(&self) -> Result<Vec<Summary>> {
        let url = self.server.join("api/auth")?;
        let (message, signature) = self.self_signed().await?;

        let response = self
            .http_client
            .get(url)
            .header(AUTHORIZATION, bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, bs58::encode(&message).into_string())
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
        let signature = encode_signature(self.signer.sign(&message).await?)?;

        let response = self
            .http_client
            .get(url)
            .header(AUTHORIZATION, bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, bs58::encode(&message).into_string())
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

    async fn create_wal(
        &self,
        vault: Vec<u8>,
    ) -> Result<(StatusCode, Option<CommitProof>)> {
        let url = self.server.join("api/vaults")?;
        let signature = encode_signature(self.signer.sign(&vault).await?)?;
        let response = self
            .http_client
            .put(url)
            .header(AUTHORIZATION, bearer_prefix(&signature))
            .header(CONTENT_TYPE, MIME_TYPE_VAULT)
            .body(vault)
            .send()
            .await?;
        let headers = response.headers();
        let server_proof = decode_headers_proof(headers)?;
        Ok((
            StatusCode::from_u16(response.status().into())?,
            server_proof,
        ))
    }

    /// Get the WAL bytes for a vault.
    async fn get_wal(
        &self,
        vault_id: &Uuid,
        proof: Option<&CommitProof>,
    ) -> Result<(StatusCode, Option<CommitProof>, Option<Vec<u8>>)> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        let (message, signature) = self.self_signed().await?;
        let mut builder = self
            .http_client
            .get(url)
            .header(AUTHORIZATION, bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, bs58::encode(&message).into_string());

        if let Some(proof) = proof {
            builder = encode_headers_proof(builder, proof)?;
        }

        let response = builder.send().await?;
        let headers = response.headers();
        let server_proof = decode_headers_proof(headers)?;
        let status_code: u16 = response.status().into();
        let buffer = if response.status().is_success() {
            Some(response.bytes().await?.to_vec())
        } else {
            None
        };

        Ok((StatusCode::from_u16(status_code)?, server_proof, buffer))
    }

    async fn post_wal(
        &self,
        vault_id: &Uuid,
        proof: &CommitProof,
        body: Vec<u8>,
    ) -> Result<(StatusCode, Option<CommitProof>)> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        let signature = encode_signature(self.signer.sign(&body).await?)?;
        let mut builder = self
            .http_client
            .post(url)
            .header(AUTHORIZATION, bearer_prefix(&signature))
            .header(CONTENT_TYPE, MIME_TYPE_VAULT)
            .body(body);

        builder = encode_headers_proof(builder, proof)?;

        let response = builder.send().await?;
        let headers = response.headers();
        let server_proof = decode_headers_proof(headers)?;
        Ok((
            StatusCode::from_u16(response.status().into())?,
            server_proof,
        ))
    }

    async fn patch_wal(
        &self,
        vault_id: &Uuid,
        proof: &CommitProof,
        patch: &Patch<'_>,
    ) -> Result<(StatusCode, Option<CommitProof>, Option<CommitProof>)> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        let message = encode(&*patch)?;

        let signature = encode_signature(self.signer.sign(&message).await?)?;

        let mut builder = self
            .http_client
            .patch(url)
            .header(AUTHORIZATION, bearer_prefix(&signature));

        builder = encode_headers_proof(builder, proof)?;
        builder = builder.body(message);

        let response = builder.send().await?;
        let headers = response.headers();
        let server_proof = decode_headers_proof(headers)?;
        let match_proof = decode_match_proof(headers)?;

        Ok((
            StatusCode::from_u16(response.status().into())?,
            server_proof,
            match_proof,
        ))
    }

    async fn head_wal(
        &self,
        vault_id: &Uuid,
        proof: Option<&CommitProof>,
    ) -> Result<(StatusCode, CommitProof, Option<CommitProof>)> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        let (message, signature) = self.self_signed().await?;
        let mut builder = self
            .http_client
            .head(url)
            .header(AUTHORIZATION, bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, bs58::encode(&message).into_string());

        if let Some(proof) = proof {
            builder = encode_headers_proof(builder, proof)?;
        }

        let response = builder.send().await?;
        let headers = response.headers();

        let server_proof =
            decode_headers_proof(headers)?.ok_or(Error::ServerProof)?;
        let match_proof = decode_match_proof(headers)?;
        Ok((
            StatusCode::from_u16(response.status().into())?,
            server_proof,
            match_proof,
        ))
    }

    async fn delete_wal(
        &self,
        vault_id: &Uuid,
    ) -> Result<(StatusCode, Option<CommitProof>)> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        let (message, signature) = self.self_signed().await?;
        let response = self
            .http_client
            .delete(url)
            .header(AUTHORIZATION, bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, bs58::encode(&message).into_string())
            .send()
            .await?;
        let headers = response.headers();
        let server_proof = decode_headers_proof(headers)?;
        Ok((
            StatusCode::from_u16(response.status().into())?,
            server_proof,
        ))
    }

    async fn put_vault(
        &self,
        vault_id: &Uuid,
        vault: Vec<u8>,
    ) -> Result<(StatusCode, Option<CommitProof>)> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        let signature = encode_signature(self.signer.sign(&vault).await?)?;

        let response = self
            .http_client
            .put(url)
            .header(AUTHORIZATION, bearer_prefix(&signature))
            .header(CONTENT_TYPE, MIME_TYPE_VAULT)
            .body(vault)
            .send()
            .await?;

        let headers = response.headers();
        let server_proof = decode_headers_proof(headers)?;
        Ok((
            StatusCode::from_u16(response.status().into())?,
            server_proof,
        ))
    }
}

impl RequestClient {
    /// Create a new client.
    pub fn new(server: Url, signer: Arc<dyn Signer + Send + Sync>) -> Self {
        let http_client = reqwest::Client::new();
        Self {
            server,
            http_client,
            signer,
        }
    }

    async fn self_signed(&self) -> Result<(Vec<u8>, String)> {
        let message: [u8; 32] = rand::thread_rng().gen();
        let signature = encode_signature(self.signer.sign(&message).await?)?;
        Ok((message.to_vec(), signature))
    }

    /// Generic GET function.
    pub async fn get(&self, url: Url) -> Result<Response> {
        Ok(self.http_client.get(url).send().await?)
    }

    /// Get the server information.
    pub async fn server_info(&self) -> Result<Response> {
        let url = self.server.join("api")?;
        let response = self.http_client.get(url).send().await?;
        Ok(response)
    }

    /// Get an event source for the changes feed.
    async fn events(&self) -> Result<EventSource> {
        let message: [u8; 32] = rand::thread_rng().gen();
        let token = encode_signature(self.signer.sign(&message).await?)?;
        let message = hex::encode(&message);
        let mut url = self.server.join("/api/changes")?;
        url.query_pairs_mut()
            .append_pair("message", &message)
            .append_pair("token", &token);
        Ok(EventSource::get(url))
    }

    /// Get a stream of change notifications.
    pub async fn changes(&self) -> Result<ChangeStream> {
        Ok(ChangeStream::new(self.events().await?))
    }
}
