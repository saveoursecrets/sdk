//! Remote procedure call (RPC) client implementation.
use http::StatusCode;
use serde::{de::DeserializeOwned, Serialize};
use sos_core::{
    commit_tree::CommitProof,
    constants::{
        ACCOUNT_CREATE, ACCOUNT_LIST_VAULTS, SESSION_OFFER, SESSION_VERIFY,
        VAULT_CREATE, X_SESSION,
    },
    crypto::AeadPack,
    decode, encode,
    rpc::{Packet, RequestMessage, ResponseMessage},
    signer::BoxedSigner,
    vault::Summary,
};
use std::borrow::Cow;
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

/// Read a response to an RPC call.
async fn read_rpc_call<T: DeserializeOwned>(
    response: reqwest::Response,
    session: Option<&mut ClientSession>,
) -> Result<(StatusCode, sos_core::Result<T>)> {
    let buffer = response.bytes().await?;

    let buffer = if let Some(session) = session {
        let aead: AeadPack = decode(&buffer)?;
        session.decrypt(&aead)?
    } else {
        buffer.to_vec()
    };

    let reply: Packet<'static> = decode(&buffer)?;
    let response: ResponseMessage<'static> = reply.try_into()?;
    let (_, status, result, _) = response.take::<T>()?;
    let result = result.ok_or(Error::NoReturnValue)?;

    Ok((status, result))
}

/// Make an encrypted session request.
async fn session_request(
    client: &reqwest::Client,
    url: Url,
    session_id: Uuid,
    session: &mut ClientSession,
    request: Vec<u8>,
) -> Result<reqwest::Response> {
    let aead = session.encrypt(&request)?;
    let body = encode(&aead)?;
    let response = client
        .post(url)
        .header(X_SESSION, session_id.to_string())
        .body(body)
        .send()
        .await?;
    Ok(response)
}

/// Client implementation for RPC requests.
pub struct RpcClient {
    server: Url,
    signer: BoxedSigner,
    client: reqwest::Client,
    session: Option<ClientSession>,
    id: u64,
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
            id: 0,
        }
    }

    /// Get the signer for this client.
    pub fn signer(&self) -> &BoxedSigner {
        &self.signer
    }

    /// Get the session.
    pub fn session(&self) -> Option<&ClientSession> {
        self.session.as_ref()
    }

    /// Get the next request identifier.
    fn next_id(&mut self) -> u64 {
        self.id += 1;
        self.id
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

        let (_status, result) =
            read_rpc_call::<(Uuid, [u8; 16], Vec<u8>)>(response, None)
                .await?;
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
        let (_status, result) = read_rpc_call::<()>(response, None).await?;
        let _result = result?;

        // Store the session for later requests
        session.finish(client_key);
        self.session = Some(session);

        Ok(())
    }

    /// Create a new account.
    pub async fn create_account(
        &mut self,
        vault: Vec<u8>,
    ) -> Result<StatusCode> {
        let id = self.next_id();
        let session = self.session.as_mut().ok_or(Error::NoSession)?;
        session.ready().then_some(()).ok_or(Error::InvalidSession)?;

        let url = self.server.join("api/account")?;
        let session_id = session.id().clone();

        let request = new_rpc_body(id, ACCOUNT_CREATE, (), vault)?;

        let response =
            session_request(&self.client, url, session_id, session, request)
                .await?;

        let (status, _) =
            read_rpc_call::<()>(response, Some(session)).await?;

        // Note we need to pass the 409 conflict response back
        // to the caller
        if status.is_server_error() {
            return Err(Error::ResponseCode(status.into()));
        }

        Ok(status)
    }

    /// List vaults for an account.
    pub async fn list_vaults(&mut self) -> Result<Vec<Summary>> {
        let id = self.next_id();
        let session = self.session.as_mut().ok_or(Error::NoSession)?;
        session.ready().then_some(()).ok_or(Error::InvalidSession)?;

        let url = self.server.join("api/account")?;
        let session_id = session.id().clone();

        let request = new_rpc_call(id, ACCOUNT_LIST_VAULTS, ())?;

        let response =
            session_request(&self.client, url, session_id, session, request)
                .await?;

        let (status, result) =
            read_rpc_call::<Vec<Summary>>(response, Some(session)).await?;

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        Ok(result?)
    }

    /// Create a new vault on a remote node.
    pub async fn create_vault(
        &mut self,
        vault: Vec<u8>,
    ) -> Result<(StatusCode, Option<CommitProof>)> {
        let id = self.next_id();
        let session = self.session.as_mut().ok_or(Error::NoSession)?;
        session.ready().then_some(()).ok_or(Error::InvalidSession)?;

        let url = self.server.join("api/vault")?;
        let session_id = session.id().clone();

        let request = new_rpc_body(id, VAULT_CREATE, (), vault)?;

        let response =
            session_request(&self.client, url, session_id, session, request)
                .await?;

        let (status, result) =
            read_rpc_call::<Option<CommitProof>>(response, Some(session))
                .await?;

        // We need to pass the 409 conflict response back
        // to the caller
        if status.is_server_error() {
            return Err(Error::ResponseCode(status.into()));
        }

        Ok((status, result?))
    }
}
