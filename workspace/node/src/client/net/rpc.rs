//! Remote procedure call (RPC) client implementation.
use serde::{de::DeserializeOwned, Serialize};
use sos_core::{
    commit_tree::CommitProof,
    constants::{SESSION_OFFER, SESSION_VERIFY},
    decode, encode,
    rpc::{Packet, RequestMessage, ResponseMessage},
    signer::BoxedSigner,
    vault::Summary,
    Patch,
};
use url::Url;
use uuid::Uuid;
use http::StatusCode;

use crate::{
    client::{Error, Result},
    session::ClientSession,
};

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

    /// Create an RPC call without a body.
    fn new_rpc_call<T: Serialize>(
        &mut self,
        method: &str,
        params: T,
    ) -> Result<Vec<u8>> {
        let id = self.next_id();
        let request = RequestMessage::new_call(Some(id), method, params)?;
        let packet = Packet::new_request(request);
        let body = encode(&packet)?;
        Ok(body)
    }

    /// Read a response to an RPC call.
    async fn read_rpc_call<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<(StatusCode, T)> {
        let buffer = response.bytes().await?;
        let reply: Packet<'static> = decode(&buffer)?;
        let response: ResponseMessage<'static> = reply.try_into()?;
        let (_, status, result, _) = response.take::<T>()?;
        let result = result.ok_or(Error::NoReturnValue)?;
        Ok((status, result?))
    }

    /// Attempt to authenticate to the remote node and store
    /// the client session.
    pub async fn authenticate(&mut self) -> Result<()> {
        let url = self.server.join("api/session")?;

        // Offer
        let address = self.signer.address()?;
        let body = self.new_rpc_call(SESSION_OFFER, address)?;

        let response =
            self.client.post(url.clone()).body(body).send().await?;

        response
            .status()
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(response.status().into()))?;

        let (_status, result) = self
            .read_rpc_call::<(Uuid, [u8; 16], Vec<u8>)>(response)
            .await?;
        let (session_id, challenge, public_key) = result;

        // Verify
        let mut session =
            ClientSession::new(self.signer.clone(), session_id)?;
        let (signature, client_key) =
            session.sign(&public_key, challenge).await?;

        let body = self.new_rpc_call(
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
        self.read_rpc_call::<()>(response).await?;

        // Store the session for later requests
        session.finish(client_key);
        self.session = Some(session);

        Ok(())
    }

    /// Create a new account.
    pub async fn create_account(&self, vault: Vec<u8>) -> Result<StatusCode> {
        

        /*
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
        */
    }
}
