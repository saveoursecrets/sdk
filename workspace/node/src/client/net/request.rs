//! HTTP client implementations.
use async_trait::async_trait;
use http::StatusCode;
use rand::Rng;
use reqwest::{header::HeaderMap, RequestBuilder, Response};

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
use url::Url;
use uuid::Uuid;

use crate::client::{Error, Result};

use super::{bearer_prefix, encode_signature, Challenge, NetworkClient};

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

async fn self_signed(
    signer: &(impl Signer + Send + Sync + 'static),
) -> Result<(Vec<u8>, String)> {
    let message: [u8; 32] = rand::thread_rng().gen();
    let signature = encode_signature(signer.sign(&message).await?)?;
    Ok((message.to_vec(), signature))
}

macro_rules! create_account {
    ($server:expr, $http_client:expr, $signer:expr, $vault:expr) => {{
        let url = $server.join("api/accounts")?;
        let signature = encode_signature($signer.sign(&$vault).await?)?;
        let response = $http_client
            .put(url)
            .header(AUTHORIZATION, bearer_prefix(&signature))
            .header(CONTENT_TYPE, MIME_TYPE_VAULT)
            .body($vault)
            .send()
            .await?;
        Ok(StatusCode::from_u16(response.status().into())?)
    }};
}

macro_rules! list_vaults {
    ($server:expr, $http_client:expr, $signer:expr) => {{
        let url = $server.join("api/auth")?;
        let (message, signature) = self_signed($signer).await?;

        let response = $http_client
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
        let url = $server.join(&url)?;
        let signature = encode_signature($signer.sign(&message).await?)?;

        let response = $http_client
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
    }};
}

macro_rules! create_wal {
    ($server:expr, $http_client:expr, $signer:expr, $vault:expr) => {{
        let url = $server.join("api/vaults")?;
        let signature = encode_signature($signer.sign(&$vault).await?)?;
        let response = $http_client
            .put(url)
            .header(AUTHORIZATION, bearer_prefix(&signature))
            .header(CONTENT_TYPE, MIME_TYPE_VAULT)
            .body($vault)
            .send()
            .await?;
        let headers = response.headers();
        let server_proof = decode_headers_proof(headers)?;
        Ok((
            StatusCode::from_u16(response.status().into())?,
            server_proof,
        ))
    }};
}

macro_rules! get_wal {
    ($server:expr, $http_client:expr, $signer:expr, $vault_id:expr, $proof:expr) => {{
        let url = $server.join(&format!("api/vaults/{}", $vault_id))?;
        let (message, signature) = self_signed($signer).await?;
        let mut builder = $http_client
            .get(url)
            .header(AUTHORIZATION, bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, bs58::encode(&message).into_string());

        if let Some(proof) = $proof {
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
    }};
}

macro_rules! post_wal {
    ($server:expr, $http_client:expr, $signer:expr, $vault_id:expr, $proof:expr, $body:expr) => {{
        let url = $server.join(&format!("api/vaults/{}", $vault_id))?;
        let signature = encode_signature($signer.sign(&$body).await?)?;
        let mut builder = $http_client
            .post(url)
            .header(AUTHORIZATION, bearer_prefix(&signature))
            .header(CONTENT_TYPE, MIME_TYPE_VAULT)
            .body($body);

        builder = encode_headers_proof(builder, $proof)?;

        let response = builder.send().await?;
        let headers = response.headers();
        let server_proof = decode_headers_proof(headers)?;
        Ok((
            StatusCode::from_u16(response.status().into())?,
            server_proof,
        ))
    }};
}

macro_rules! patch_wal {
    ($server:expr, $http_client:expr, $signer:expr, $vault_id:expr, $proof:expr, $patch:expr) => {{
        let url = $server.join(&format!("api/vaults/{}", $vault_id))?;
        let message = encode($patch)?;

        let signature = encode_signature($signer.sign(&message).await?)?;

        let mut builder = $http_client
            .patch(url)
            .header(AUTHORIZATION, bearer_prefix(&signature));

        builder = encode_headers_proof(builder, $proof)?;
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
    }};
}

macro_rules! head_wal {
    ($server:expr, $http_client:expr, $signer:expr, $vault_id:expr, $proof:expr) => {{
        let url = $server.join(&format!("api/vaults/{}", $vault_id))?;
        let (message, signature) = self_signed($signer).await?;
        let mut builder = $http_client
            .head(url)
            .header(AUTHORIZATION, bearer_prefix(&signature))
            .header(X_SIGNED_MESSAGE, bs58::encode(&message).into_string());

        if let Some(proof) = $proof {
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
    }};
}

macro_rules! delete_wal {
    ($server:expr, $http_client:expr, $signer:expr, $vault_id:expr) => {{
        let url = $server.join(&format!("api/vaults/{}", $vault_id))?;
        let (message, signature) = self_signed($signer).await?;
        let response = $http_client
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
    }};
}

macro_rules! put_vault {
    ($server:expr, $http_client:expr, $signer:expr, $vault_id:expr, $vault:expr) => {{
        let url = $server.join(&format!("api/vaults/{}", $vault_id))?;
        let signature = encode_signature($signer.sign(&$vault).await?)?;

        let response = $http_client
            .put(url)
            .header(AUTHORIZATION, bearer_prefix(&signature))
            .header(CONTENT_TYPE, MIME_TYPE_VAULT)
            .body($vault)
            .send()
            .await?;

        let headers = response.headers();
        let server_proof = decode_headers_proof(headers)?;
        Ok((
            StatusCode::from_u16(response.status().into())?,
            server_proof,
        ))
    }};
}

/// HTTP client implementation using the `reqwest` library.
#[derive(Clone)]
pub struct RequestClient<T: Signer + Send + Sync + 'static> {
    server: Url,
    http_client: reqwest::Client,
    signer: T,
}

impl<T: Signer + Send + Sync + 'static> RequestClient<T> {
    /// Create a new client.
    pub fn new(server: Url, signer: T) -> Self {
        let http_client = reqwest::Client::new();
        Self {
            server,
            http_client,
            signer,
        }
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
    #[cfg(not(target_arch = "wasm32"))]
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
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn changes(&self) -> Result<ChangeStream> {
        Ok(ChangeStream::new(self.events().await?))
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<S: Signer + Send + Sync + 'static> NetworkClient for RequestClient<S> {
    fn address(&self) -> Result<AddressStr> {
        Ok(self.signer.address()?)
    }

    async fn create_account(&self, vault: Vec<u8>) -> Result<StatusCode> {
        let result = create_account!(
            &self.server,
            &self.http_client,
            &self.signer,
            vault
        );
        result
    }

    async fn list_vaults(&self) -> Result<Vec<Summary>> {
        let result =
            list_vaults!(&self.server, &self.http_client, &self.signer);
        result
    }

    async fn create_wal(
        &self,
        vault: Vec<u8>,
    ) -> Result<(StatusCode, Option<CommitProof>)> {
        let result =
            create_wal!(&self.server, &self.http_client, &self.signer, vault);
        result
    }

    /// Get the WAL bytes for a vault.
    async fn get_wal(
        &self,
        vault_id: &Uuid,
        proof: Option<&CommitProof>,
    ) -> Result<(StatusCode, Option<CommitProof>, Option<Vec<u8>>)> {
        let result = get_wal!(
            &self.server,
            &self.http_client,
            &self.signer,
            vault_id,
            proof
        );
        result
    }

    async fn post_wal(
        &self,
        vault_id: &Uuid,
        proof: &CommitProof,
        body: Vec<u8>,
    ) -> Result<(StatusCode, Option<CommitProof>)> {
        let result = post_wal!(
            &self.server,
            &self.http_client,
            &self.signer,
            vault_id,
            proof,
            body
        );
        result
    }

    async fn patch_wal(
        &self,
        vault_id: &Uuid,
        proof: &CommitProof,
        patch: &Patch<'_>,
    ) -> Result<(StatusCode, Option<CommitProof>, Option<CommitProof>)> {
        let result = patch_wal!(
            &self.server,
            &self.http_client,
            &self.signer,
            vault_id,
            proof,
            patch
        );
        result
    }

    async fn head_wal(
        &self,
        vault_id: &Uuid,
        proof: Option<&CommitProof>,
    ) -> Result<(StatusCode, CommitProof, Option<CommitProof>)> {
        let result = head_wal!(
            &self.server,
            &self.http_client,
            &self.signer,
            vault_id,
            proof
        );
        result
    }

    async fn delete_wal(
        &self,
        vault_id: &Uuid,
    ) -> Result<(StatusCode, Option<CommitProof>)> {
        let result = delete_wal!(
            &self.server,
            &self.http_client,
            &self.signer,
            vault_id
        );
        result
    }

    async fn put_vault(
        &self,
        vault_id: &Uuid,
        vault: Vec<u8>,
    ) -> Result<(StatusCode, Option<CommitProof>)> {
        let result = put_vault!(
            &self.server,
            &self.http_client,
            &self.signer,
            vault_id,
            vault
        );
        result
    }
}

/// Client implementation that yields static
/// futures for use in webassembly.
#[cfg(target_arch = "wasm32")]
pub struct StaticClient;

#[cfg(target_arch = "wasm32")]
impl StaticClient {
    /// Create an account.
    pub fn create_account(
        server: Url,
        signer: impl Signer + Send + Sync + 'static,
        vault: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<StatusCode>> + 'static {
        async move {
            let client = reqwest::Client::new();
            let result = create_account!(server, client, &signer, vault);
            result
        }
    }

    /// List vaults.
    pub fn list_vaults(
        server: Url,
        signer: impl Signer + Send + Sync + 'static,
    ) -> impl std::future::Future<Output = Result<Vec<Summary>>> + 'static
    {
        async move {
            let client = reqwest::Client::new();
            let result = list_vaults!(server, client, &signer);
            result
        }
    }

    /// Create a WAL on the remote node.
    pub fn create_wal(
        server: Url,
        signer: impl Signer + Send + Sync + 'static,
        vault: Vec<u8>,
    ) -> impl std::future::Future<
        Output = Result<(StatusCode, Option<CommitProof>)>,
    > + 'static {
        async move {
            let client = reqwest::Client::new();
            let result = create_wal!(server, client, &signer, vault);
            result
        }
    }

    /// Get a WAL from the remote node.
    pub fn get_wal(
        server: Url,
        signer: impl Signer + Send + Sync + 'static,
        vault_id: Uuid,
        proof: Option<CommitProof>,
    ) -> impl std::future::Future<
        Output = Result<(StatusCode, Option<CommitProof>, Option<Vec<u8>>)>,
    > + 'static {
        async move {
            let client = reqwest::Client::new();
            let result =
                get_wal!(server, client, &signer, vault_id, proof.as_ref());
            result
        }
    }

    /// Send a WAL to the remote node.
    pub fn post_wal(
        server: Url,
        signer: impl Signer + Send + Sync + 'static,
        vault_id: Uuid,
        proof: CommitProof,
        body: Vec<u8>,
    ) -> impl std::future::Future<
        Output = Result<(StatusCode, Option<CommitProof>)>,
    > + 'static {
        async move {
            let client = reqwest::Client::new();
            let result =
                post_wal!(server, client, &signer, vault_id, &proof, body);
            result
        }
    }

    /// Send a patch for a WAL on a remote node.
    pub fn patch_wal(
        server: Url,
        signer: impl Signer + Send + Sync + 'static,
        vault_id: Uuid,
        proof: CommitProof,
        patch: Patch<'static>,
    ) -> impl std::future::Future<
        Output = Result<(
            StatusCode,
            Option<CommitProof>,
            Option<CommitProof>,
        )>,
    > + 'static {
        async move {
            let client = reqwest::Client::new();
            let result =
                patch_wal!(server, client, &signer, vault_id, &proof, &patch);
            result
        }
    }

    /// Get WAL information from a remote node.
    pub fn head_wal(
        server: Url,
        signer: impl Signer + Send + Sync + 'static,
        vault_id: Uuid,
        proof: Option<CommitProof>,
    ) -> impl std::future::Future<
        Output = Result<(StatusCode, CommitProof, Option<CommitProof>)>,
    > + 'static {
        async move {
            let client = reqwest::Client::new();
            let result = head_wal!(server, client, &signer, vault_id, &proof);
            result
        }
    }

    /// Delete a WAL from a remote node.
    pub fn delete_wal(
        server: Url,
        signer: impl Signer + Send + Sync + 'static,
        vault_id: Uuid,
    ) -> impl std::future::Future<
        Output = Result<(StatusCode, Option<CommitProof>)>,
    > + 'static {
        async move {
            let client = reqwest::Client::new();
            let result = delete_wal!(server, client, &signer, vault_id);
            result
        }
    }

    /// Overwrite a vault on a remote node.
    pub fn put_vault(
        server: Url,
        signer: impl Signer + Send + Sync + 'static,
        vault_id: Uuid,
        vault: Vec<u8>,
    ) -> impl std::future::Future<
        Output = Result<(StatusCode, Option<CommitProof>)>,
    > + 'static {
        async move {
            let client = reqwest::Client::new();
            let result = put_vault!(server, client, &signer, vault_id, vault);
            result
        }
    }
}
