//! HTTP client trait and implementations.
use async_trait::async_trait;
use http::StatusCode;
use sos_core::{
    address::AddressStr,
    commit_tree::CommitProof,
    vault::{Summary},
    Patch,
};

use web3_signature::Signature;
use url::Url;
use uuid::Uuid;
use super::{Result};

pub mod request;
pub use request::RequestClient;

pub(crate) type Challenge = [u8; 32];

pub(crate) fn encode_signature(signature: Signature) -> Result<String> {
    Ok(base64::encode(serde_json::to_string(&signature)?))
}

pub(crate) fn bearer_prefix(signature: &str) -> String {
    format!("Bearer {}", signature)
}

/*

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

fn decode_match_proof(headers: &HeaderMap) -> Result<Option<CommitProof>> {
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
*/

/// Trait for HTTP client implementations.
#[async_trait]
pub trait HttpClient {
    /// Get the server URL.
    fn server(&self) -> &Url;

    /// Compute the address of the current signer.
    fn address(&self) -> Result<AddressStr>;

    /// List the vaults accessible by this signer.
    async fn list_vaults(&self) -> Result<Vec<Summary>>;

    /// Create a new account.
    async fn create_account(&self, vault: Vec<u8>) -> Result<StatusCode>;

    /// Create a new WAL file on a remote node.
    async fn create_wal(
        &self,
        vault: Vec<u8>,
    ) -> Result<(StatusCode, Option<CommitProof>)>;

    /// Get the WAL bytes for a vault.
    async fn get_wal(
        &self,
        vault_id: &Uuid,
        proof: Option<&CommitProof>,
    ) -> Result<(StatusCode, Option<CommitProof>, Option<Vec<u8>>)>;

    /// Replace a WAL file on a remote node.
    async fn post_wal(
        &self,
        vault_id: &Uuid,
        proof: &CommitProof,
        body: Vec<u8>,
    ) -> Result<(StatusCode, Option<CommitProof>)>;

    /// Apply events to the WAL file on a remote node.
    async fn patch_wal(
        &self,
        vault_id: &Uuid,
        proof: &CommitProof,
        patch: &Patch<'_>,
    ) -> Result<(StatusCode, Option<CommitProof>, Option<CommitProof>)>;

    /// Get the commit proof for the WAL file on a remote node.
    async fn head_wal(
        &self,
        vault_id: &Uuid,
        proof: Option<&CommitProof>,
    ) -> Result<(StatusCode, CommitProof, Option<CommitProof>)>;

    /// Delete a WAL file on a remote node.
    async fn delete_wal(
        &self,
        vault_id: &Uuid,
    ) -> Result<(StatusCode, Option<CommitProof>)>;

    /// Update an existing vault.
    async fn put_vault(
        &self,
        vault_id: &Uuid,
        vault: Vec<u8>,
    ) -> Result<(StatusCode, Option<CommitProof>)>;
}
