//! HTTP client implementation.
//!
//! Uses futures with a `'static` lifetime so it may also be
//! used in webassembly.

use http::StatusCode;
use rand::Rng;
use reqwest::{header::HeaderMap, RequestBuilder, Response};
use std::future::Future;

use sos_core::{
    commit_tree::CommitProof,
    constants::{
        MIME_TYPE_VAULT, X_COMMIT_PROOF, X_MATCH_PROOF, X_SIGNED_MESSAGE,
    },
    decode, encode,
    signer::BoxedSigner,
    vault::Summary,
    Patch,
};
use url::Url;
use uuid::Uuid;

use crate::client::{Error, Result};

use super::{bearer_prefix, encode_signature, Challenge};

#[cfg(not(target_arch = "wasm32"))]
use reqwest_eventsource::EventSource;

#[cfg(not(target_arch = "wasm32"))]
use super::changes::ChangeStream;

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

async fn self_signed(signer: &BoxedSigner) -> Result<(Vec<u8>, String)> {
    let message: [u8; 32] = rand::thread_rng().gen();
    let signature = encode_signature(signer.sign(&message).await?)?;
    Ok((message.to_vec(), signature))
}

/// HTTP client implementation using the `reqwest` library.
#[derive(Clone)]
pub struct RequestClient {
    server: Url,
    signer: BoxedSigner,
    client: reqwest::Client,
}

impl RequestClient {
    /// Create a new request client.
    pub fn new(server: Url, signer: BoxedSigner) -> Self {
        let client = reqwest::Client::new();
        Self {
            server,
            signer,
            client,
        }
    }

    /// Get the signer for this client.
    pub fn signer(&self) -> &BoxedSigner {
        &self.signer
    }

    /// Generic GET function.
    pub async fn get(url: Url) -> Result<Response> {
        let client = reqwest::Client::new();
        Ok(client.get(url).send().await?)
    }

    /// Get the server information.
    pub async fn server_info(server: Url) -> Result<Response> {
        let client = reqwest::Client::new();
        let url = server.join("api")?;
        let response = client.get(url).send().await?;
        Ok(response)
    }

    /// Get the URL for a changes event source feed.
    pub fn changes_feed_url(
        server: Url,
        signer: BoxedSigner,
    ) -> impl Future<Output = Result<Url>> + 'static {
        async move {
            let message: [u8; 32] = rand::thread_rng().gen();
            let token = encode_signature(signer.sign(&message).await?)?;
            let message = hex::encode(&message);
            let mut url = server.join("/api/changes")?;
            url.query_pairs_mut()
                .append_pair("message", &message)
                .append_pair("token", &token);
            Ok(url)
        }
    }

    /// Get an event source for the changes feed.
    #[cfg(not(target_arch = "wasm32"))]
    async fn events(server: Url, signer: BoxedSigner) -> Result<EventSource> {
        let url = RequestClient::changes_feed_url(server, signer).await?;
        Ok(EventSource::get(url))
    }

    /// Get a stream of change notifications.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn changes(
        server: Url,
        signer: BoxedSigner,
    ) -> Result<ChangeStream> {
        Ok(ChangeStream::new(
            RequestClient::events(server, signer).await?,
        ))
    }

    /// Create a new account.
    pub async fn create_account(&self, vault: Vec<u8>) -> Result<StatusCode> {
        let url = self.server.join("api/accounts")?;
        let signature = encode_signature(self.signer.sign(&vault).await?)?;
        let response = self
            .client
            .put(url)
            .header(AUTHORIZATION, bearer_prefix(&signature))
            .header(CONTENT_TYPE, MIME_TYPE_VAULT)
            .body(vault)
            .send()
            .await?;
        Ok(StatusCode::from_u16(response.status().into())?)
    }

    /// List the vaults accessible by this signer.
    pub async fn list_vaults(&self) -> Result<Vec<Summary>> {
        let url = self.server.join("api/auth")?;
        let (message, signature) = self_signed(&self.signer).await?;

        let response = self
            .client
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
            .client
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

    /// Create a new WAL file on a remote node.
    pub async fn create_wal(
        &self,
        vault: Vec<u8>,
    ) -> Result<(StatusCode, Option<CommitProof>)> {
        let url = self.server.join("api/vaults")?;
        let signature = encode_signature(self.signer.sign(&vault).await?)?;
        let response = self
            .client
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
    pub async fn get_wal(
        &self,
        vault_id: Uuid,
        proof: Option<CommitProof>,
    ) -> Result<(StatusCode, Option<CommitProof>, Option<Vec<u8>>)> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        let (message, signature) = self_signed(&self.signer).await?;
        let mut builder = self
            .client
            .get(url)
            .header(AUTHORIZATION, bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, bs58::encode(&message).into_string());

        if let Some(proof) = &proof {
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

    /// Replace a WAL file on a remote node.
    pub async fn post_wal(
        &self,
        vault_id: Uuid,
        proof: CommitProof,
        body: Vec<u8>,
    ) -> Result<(StatusCode, Option<CommitProof>)> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        let signature = encode_signature(self.signer.sign(&body).await?)?;
        let mut builder = self
            .client
            .post(url)
            .header(AUTHORIZATION, bearer_prefix(&signature))
            .header(CONTENT_TYPE, MIME_TYPE_VAULT)
            .body(body);

        builder = encode_headers_proof(builder, &proof)?;

        let response = builder.send().await?;
        let headers = response.headers();
        let server_proof = decode_headers_proof(headers)?;
        Ok((
            StatusCode::from_u16(response.status().into())?,
            server_proof,
        ))
    }

    /// Apply events to the WAL file on a remote node.
    pub async fn patch_wal(
        &self,
        vault_id: Uuid,
        proof: CommitProof,
        patch: Patch<'static>,
    ) -> Result<(StatusCode, Option<CommitProof>, Option<CommitProof>)> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        let message = encode(&patch)?;

        let signature = encode_signature(self.signer.sign(&message).await?)?;

        let mut builder = self
            .client
            .patch(url)
            .header(AUTHORIZATION, bearer_prefix(&signature));

        builder = encode_headers_proof(builder, &proof)?;
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

    /// Get the commit proof for the WAL file on a remote node.
    pub async fn head_wal(
        &self,
        vault_id: Uuid,
        proof: Option<CommitProof>,
    ) -> Result<(StatusCode, CommitProof, Option<CommitProof>)> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        let (message, signature) = self_signed(&self.signer).await?;
        let mut builder = self
            .client
            .head(url)
            .header(AUTHORIZATION, bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, bs58::encode(&message).into_string());

        if let Some(proof) = &proof {
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

    /// Delete a WAL file on a remote node.
    pub async fn delete_wal(
        &self,
        vault_id: Uuid,
    ) -> Result<(StatusCode, Option<CommitProof>)> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        let (message, signature) = self_signed(&self.signer).await?;
        let response = self
            .client
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

    /// Update an existing vault.
    ///
    /// This should be used when the commit tree has been
    /// rewritten, for example if the history was compacted
    /// or the password for a vault was changed.
    pub async fn put_vault(
        &self,
        vault_id: Uuid,
        vault: Vec<u8>,
    ) -> Result<(StatusCode, Option<CommitProof>)> {
        let url = self.server.join(&format!("api/vaults/{}", vault_id))?;
        let signature = encode_signature(self.signer.sign(&vault).await?)?;

        let response = self
            .client
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
