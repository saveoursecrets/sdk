//! HTTP transport trait and implementations.
use async_trait::async_trait;
use http::StatusCode;
use sos_core::{
    address::AddressStr, commit_tree::CommitProof, vault::Summary, Patch,
};

use super::Result;
use uuid::Uuid;
use web3_signature::Signature;

pub mod request;
pub use request::RequestClient;

pub(crate) type Challenge = [u8; 32];

pub(crate) fn encode_signature(signature: Signature) -> Result<String> {
    Ok(base64::encode(serde_json::to_string(&signature)?))
}

pub(crate) fn bearer_prefix(signature: &str) -> String {
    format!("Bearer {}", signature)
}

/// Trait for network client implementations.
#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch="wasm32"), async_trait)]
pub trait NetworkClient {
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
    ///
    /// This should be used when the commit tree has been
    /// rewritten, for example if the history was compacted
    /// or the password for a vault was changed.
    async fn put_vault(
        &self,
        vault_id: &Uuid,
        vault: Vec<u8>,
    ) -> Result<(StatusCode, Option<CommitProof>)>;
}
