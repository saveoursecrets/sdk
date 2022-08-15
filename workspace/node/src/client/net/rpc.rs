//! Remote procedure call (RPC) client implementation.
use http::StatusCode;
use serde::{de::DeserializeOwned, Serialize};
use sos_core::{
    commit_tree::CommitProof,
    constants::{
        ACCOUNT_CREATE, ACCOUNT_LIST_VAULTS, SESSION_OFFER, SESSION_VERIFY,
        VAULT_CREATE, VAULT_DELETE, VAULT_SAVE, WAL_LOAD, WAL_PATCH,
        WAL_SAVE, WAL_STATUS, X_SESSION,
    },
    crypto::AeadPack,
    decode, encode,
    rpc::{Packet, RequestMessage, ResponseMessage},
    signer::BoxedSigner,
    vault::Summary,
    Patch,
};
use std::{
    borrow::Cow,
    sync::{
        atomic::{AtomicU64, Ordering},
        RwLock,
    },
};
use url::Url;
use uuid::Uuid;

use crate::{
    client::{Error, Result},
    session::{ClientSession, EncryptedChannel},
};

/// Create an RPC call without a body.
fn new_rpc_call<T: Serialize>(
    id: u64,
    method: &str,
    params: T,
) -> Result<Vec<u8>> {
    let request = RequestMessage::new_call(Some(id), method, params)?;
    let packet = Packet::new_request(request);
    let body = encode(&packet)?;
    Ok(body)
}

/// Create an RPC call with a body.
fn new_rpc_body<T: Serialize>(
    id: u64,
    method: &str,
    params: T,
    body: Vec<u8>,
) -> Result<Vec<u8>> {
    let request =
        RequestMessage::new(Some(id), method, params, Cow::Owned(body))?;
    let packet = Packet::new_request(request);
    let body = encode(&packet)?;
    Ok(body)
}

/// Client implementation for RPC requests.
pub struct RpcClient {
    server: Url,
    signer: BoxedSigner,
    client: reqwest::Client,
    session: Option<RwLock<ClientSession>>,
    id: AtomicU64,
}

impl RpcClient {
    /// Create a new request client.
    pub fn new(server: Url, signer: BoxedSigner) -> Self {
        let client = reqwest::Client::new();
        Self {
            server,
            signer,
            client,
            session: None,
            id: AtomicU64::from(1),
        }
    }

    /// Get the signer for this client.
    pub fn signer(&self) -> &BoxedSigner {
        &self.signer
    }

    /// Determine if this client has a session set.
    pub fn has_session(&self) -> bool {
        self.session.is_some()
    }

    /// Determine if this client's session is ready for use.
    pub fn is_ready(&self) -> Result<bool> {
        let lock = self.session.as_ref().ok_or(Error::NoSession)?;
        let session = lock.read().unwrap();
        Ok(session.ready())
    }

    /// Get the next request identifier.
    fn next_id(&self) -> u64 {
        self.id.fetch_add(1, Ordering::SeqCst)
    }

    /// Attempt to authenticate to the remote node and store
    /// the client session.
    pub async fn authenticate(&mut self) -> Result<()> {
        let url = self.server.join("api/session")?;

        // Offer
        let address = self.signer.address()?;
        let body = new_rpc_call(self.next_id(), SESSION_OFFER, address)?;

        let response =
            self.client.post(url.clone()).body(body).send().await?;

        response
            .status()
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(response.status().into()))?;

        let (_status, result, _) = self
            .read_response::<(Uuid, [u8; 16], Vec<u8>)>(
                &response.bytes().await?,
            )?;
        let result = result?;

        let (session_id, challenge, public_key) = result;

        // Verify
        let mut session =
            ClientSession::new(self.signer.clone(), session_id)?;
        let (signature, client_key) =
            session.sign(&public_key, challenge).await?;

        let body = new_rpc_call(
            self.next_id(),
            SESSION_VERIFY,
            (session_id, signature, session.public_key()),
        )?;

        let response = self.client.post(url).body(body).send().await?;
        response
            .status()
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(response.status().into()))?;

        // Check we got a success response; no error indicates success
        let (_status, result, _) =
            self.read_response::<()>(&response.bytes().await?)?;
        let _result = result?;

        // Store the session for later requests
        session.finish(client_key);
        self.session = Some(RwLock::new(session));

        Ok(())
    }

    /// Create a new account.
    pub async fn create_account(&self, vault: Vec<u8>) -> Result<StatusCode> {
        let url = self.server.join("api/account")?;
        let (session_id, body) = self.build_request(|id| {
            Ok(new_rpc_body(id, ACCOUNT_CREATE, (), vault)?)
        })?;

        let response = self.send_request(url, session_id, body).await?;

        let (status, result, _) = self
            .read_encrypted_response::<CommitProof>(
                &response.bytes().await?,
            )?;

        // Note we need to pass the 409 conflict response back
        // to the caller
        if status.is_server_error() {
            return Err(Error::ResponseCode(status.into()));
        }
        Ok(status)
    }

    /// List vaults for an account.
    pub async fn list_vaults(&self) -> Result<Vec<Summary>> {
        let url = self.server.join("api/account")?;
        let (session_id, body) = self.build_request(|id| {
            Ok(new_rpc_call(id, ACCOUNT_LIST_VAULTS, ())?)
        })?;

        let response = self.send_request(url, session_id, body).await?;

        let (status, result, _) = self
            .read_encrypted_response::<Vec<Summary>>(
                &response.bytes().await?,
            )?;

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        Ok(result?)
    }

    /* create_wal -> create_vault */

    /// Create a new vault on a remote node.
    pub async fn create_vault(
        &self,
        vault: Vec<u8>,
    ) -> Result<(StatusCode, Option<CommitProof>)> {
        let url = self.server.join("api/vault")?;
        let (session_id, body) = self.build_request(|id| {
            Ok(new_rpc_body(id, VAULT_CREATE, (), vault)?)
        })?;

        let response = self.send_request(url, session_id, body).await?;

        let (status, result, _) = self
            .read_encrypted_response::<Option<CommitProof>>(
                &response.bytes().await?,
            )?;

        // We need to pass the 409 conflict response back
        // to the caller
        if status.is_server_error() {
            return Err(Error::ResponseCode(status.into()));
        }

        Ok((status, result?))
    }

    /* delete_wal -> delete_vault */

    /// Delete a vault on a remote node.
    pub async fn delete_vault(
        &self,
        vault_id: &Uuid,
    ) -> Result<(StatusCode, Option<CommitProof>)> {
        let url = self.server.join("api/vault")?;
        let (session_id, body) = self.build_request(|id| {
            Ok(new_rpc_call(id, VAULT_DELETE, vault_id)?)
        })?;

        let response = self.send_request(url, session_id, body).await?;

        let (status, result, _) = self
            .read_encrypted_response::<Option<CommitProof>>(
                &response.bytes().await?,
            )?;

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        Ok((status, result?))
    }

    /* put_vault -> save_vault */

    /// Update an existing vault.
    ///
    /// This should be used when the commit tree has been
    /// rewritten, for example if the history was compacted
    /// or the password for a vault was changed.
    pub async fn save_vault(
        &self,
        vault_id: &Uuid,
        vault: Vec<u8>,
    ) -> Result<(StatusCode, Option<CommitProof>)> {
        let url = self.server.join("api/vault")?;
        let (session_id, body) = self.build_request(|id| {
            Ok(new_rpc_body(id, VAULT_SAVE, vault_id, vault)?)
        })?;

        let response = self.send_request(url, session_id, body).await?;

        let (status, result, _) = self
            .read_encrypted_response::<Option<CommitProof>>(
                &response.bytes().await?,
            )?;

        // We need to pass the 409 conflict response back
        // to the caller
        if status.is_server_error() {
            return Err(Error::ResponseCode(status.into()));
        }

        Ok((status, result?))
    }

    /* get_wal -> load_wal */

    /// Get the WAL bytes for a vault.
    /// TODO: remove the Option from the body return value???
    pub async fn load_wal(
        &self,
        vault_id: &Uuid,
        proof: Option<CommitProof>,
    ) -> Result<(StatusCode, Option<CommitProof>, Option<Vec<u8>>)> {
        let url = self.server.join("api/wal")?;
        let (session_id, body) = self.build_request(|id| {
            Ok(new_rpc_call(id, WAL_LOAD, (vault_id, proof))?)
        })?;

        let response = self.send_request(url, session_id, body).await?;

        let (status, result, body) = self
            .read_encrypted_response::<Option<CommitProof>>(
                &response.bytes().await?,
            )?;

        // We need to pass the 409 conflict response back
        // to the caller
        if status.is_server_error() {
            return Err(Error::ResponseCode(status.into()));
        }

        Ok((status, result?, Some(body)))
    }

    /* head_wal -> status */

    /// Get the commit proof of a vault on a remote node.
    pub async fn status(
        &self,
        vault_id: &Uuid,
        proof: Option<CommitProof>,
    ) -> Result<(StatusCode, CommitProof, Option<CommitProof>)> {
        let url = self.server.join("api/wal")?;
        let (session_id, body) = self.build_request(|id| {
            Ok(new_rpc_call(id, WAL_STATUS, (vault_id, proof))?)
        })?;

        let response = self.send_request(url, session_id, body).await?;

        let (status, result, _) = self
            .read_encrypted_response::<(CommitProof, Option<CommitProof>)>(
                &response.bytes().await?,
            )?;

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        let (server_proof, match_proof) = result?;
        Ok((status, server_proof, match_proof))
    }

    /* patch_wal -> apply */

    /// Apply a patch to the vault on a remote node.
    /// TODO: remove the Option from the server_proof ???
    pub async fn apply_patch(
        &self,
        vault_id: Uuid, /* WARN: must not be reference */
        proof: CommitProof,
        patch: Patch<'static>,
    ) -> Result<(StatusCode, Option<CommitProof>, Option<CommitProof>)> {
        let body = encode(&patch)?;
        let url = self.server.join("api/wal")?;
        let (session_id, body) = self.build_request(|id| {
            Ok(new_rpc_body(id, WAL_PATCH, (vault_id, proof), body)?)
        })?;

        let response = self.send_request(url, session_id, body).await?;

        let (status, result, _) = self
            .read_encrypted_response::<(CommitProof, Option<CommitProof>)>(
                &response.bytes().await?,
            )?;

        // We need to pass the 409 conflict response back
        // to the caller
        if status.is_server_error() {
            return Err(Error::ResponseCode(status.into()));
        }

        let (server_proof, match_proof) = result?;
        Ok((status, Some(server_proof), match_proof))
    }

    /* post_wal -> save_wal */

    /// Replace the WAL for a vault on a remote node.
    /// TODO: remove the Option from the return value ???
    pub async fn save_wal(
        &self,
        vault_id: &Uuid,
        proof: CommitProof,
        body: Vec<u8>,
    ) -> Result<(StatusCode, Option<CommitProof>)> {
        let url = self.server.join("api/wal")?;
        let (session_id, body) = self.build_request(|id| {
            Ok(new_rpc_body(id, WAL_SAVE, (vault_id, proof), body)?)
        })?;

        let response = self.send_request(url, session_id, body).await?;

        let (status, result, _) = self
            .read_encrypted_response::<CommitProof>(
                &response.bytes().await?,
            )?;

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        Ok((status, Some(result?)))
    }

    /// Build an encrypted request.
    fn build_request<F>(&self, builder: F) -> Result<(Uuid, Vec<u8>)>
    where
        F: FnOnce(u64) -> Result<Vec<u8>>,
    {
        let id = self.next_id();
        let lock = self.session.as_ref().ok_or(Error::NoSession)?;
        let mut session = lock.write().unwrap();
        session.ready().then_some(()).ok_or(Error::InvalidSession)?;

        let session_id = session.id().clone();

        let request = builder(id)?;
        let aead = session.encrypt(&request)?;
        let body = encode(&aead)?;

        Ok((session_id, body))
    }

    /// Send an encrypted session request.
    async fn send_request(
        &self,
        url: Url,
        session_id: Uuid,
        body: Vec<u8>,
    ) -> Result<reqwest::Response> {
        let response = self
            .client
            .post(url)
            .header(X_SESSION, session_id.to_string())
            .body(body)
            .send()
            .await?;
        Ok(response)
    }

    /// Read a response that is not encrypted.
    fn read_response<T: DeserializeOwned>(
        &self,
        buffer: &[u8],
    ) -> Result<(StatusCode, sos_core::Result<T>, Vec<u8>)> {
        let reply: Packet<'static> = decode(&buffer)?;
        let response: ResponseMessage<'static> = reply.try_into()?;
        let (_, status, result, body) = response.take::<T>()?;
        let result = result.ok_or(Error::NoReturnValue)?;
        Ok((status, result, body))
    }

    /// Read an encrypted response to an RPC call.
    fn read_encrypted_response<T: DeserializeOwned>(
        &self,
        buffer: &[u8],
    ) -> Result<(StatusCode, sos_core::Result<T>, Vec<u8>)> {
        let lock = self.session.as_ref().ok_or(Error::NoSession)?;
        let mut session = lock.write().unwrap();
        session.ready().then_some(()).ok_or(Error::InvalidSession)?;

        let aead: AeadPack = decode(buffer)?;
        session.set_nonce(&aead.nonce);
        let buffer = session.decrypt(&aead)?;
        let reply: Packet<'static> = decode(&buffer)?;
        let response: ResponseMessage<'static> = reply.try_into()?;

        let (_, status, result, body) = response.take::<T>()?;
        let result = result.ok_or(Error::NoReturnValue)?;
        Ok((status, result, body))
    }
}
