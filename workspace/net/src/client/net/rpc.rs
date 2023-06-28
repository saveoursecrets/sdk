//! Remote procedure call (RPC) client implementation.
use http::StatusCode;
use serde::{de::DeserializeOwned, Serialize};
use sos_sdk::{
    commit::CommitProof,
    constants::{
        ACCOUNT_CREATE, ACCOUNT_LIST_VAULTS, EVENT_LOG_LOAD, EVENT_LOG_PATCH,
        EVENT_LOG_SAVE, EVENT_LOG_STATUS, HANDSHAKE_INITIATE, SESSION_OFFER,
        SESSION_VERIFY, VAULT_CREATE, VAULT_DELETE, VAULT_SAVE, X_SESSION,
    },
    crypto::{
        channel::{ClientSession, EncryptedChannel},
        AeadPack,
    },
    decode, encode,
    mpc::{snow, Keypair, ProtocolState, PATTERN},
    patch::Patch,
    rpc::{Packet, RequestMessage, ResponseMessage},
    signer::ecdsa::BoxedEcdsaSigner,
    vault::Summary,
};
use std::{
    borrow::Cow,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::sync::RwLock;
use url::Url;
use uuid::Uuid;

use crate::client::{Error, Result};

use super::{bearer_prefix, encode_signature, AUTHORIZATION};

macro_rules! body {
    ($client:expr, $id:expr, $method:expr, $params:expr, $body:expr) => {{
        let request =
            RequestMessage::new(Some($id), $method, $params, $body)?;
        let packet = Packet::new_request(request);
        let body = encode(&packet).await?;
        $client.build_request(&body).await?
    }};
}

/// Create an RPC call without a body.
async fn new_rpc_call<T: Serialize>(
    id: u64,
    method: &str,
    params: T,
) -> Result<Vec<u8>> {
    let request = RequestMessage::new_call(Some(id), method, params)?;
    let packet = Packet::new_request(request);
    let body = encode(&packet).await?;
    Ok(body)
}

/// Client implementation for RPC requests.
pub struct RpcClient {
    server: Url,
    server_public_key: Vec<u8>,
    signer: BoxedEcdsaSigner,
    keypair: Keypair,
    protocol: ProtocolState,
    client: reqwest::Client,
    id: AtomicU64,
    #[deprecated]
    session: Option<RwLock<ClientSession>>,
}

impl RpcClient {
    /// Create a new request client.
    pub fn new(
        server: Url,
        server_public_key: Vec<u8>,
        signer: BoxedEcdsaSigner,
        keypair: Keypair,
    ) -> Result<Self> {
        let client = reqwest::Client::new();

        let mut initiator = snow::Builder::new(PATTERN.parse()?)
            .local_private_key(keypair.private_key())
            .remote_public_key(&server_public_key)
            .build_initiator()?;
        let protocol = ProtocolState::Handshake(Box::new(initiator));

        Ok(Self {
            server,
            server_public_key,
            signer,
            keypair,
            protocol,
            client,
            session: None,
            id: AtomicU64::from(1),
        })
    }

    /// Get the signer for this client.
    pub fn signer(&self) -> &BoxedEcdsaSigner {
        &self.signer
    }

    /// Get the URL for the remote node.
    pub fn remote(&self) -> &Url {
        &self.server
    }

    /// Determine if this client has a session set.
    pub fn has_session(&self) -> bool {
        self.session.is_some()
    }

    /// Get the session identifier.
    pub async fn session_id(&self) -> Result<Uuid> {
        let lock = self.session.as_ref().ok_or(Error::NoSession)?;
        let reader = lock.read().await;
        let id = *reader.id();
        Ok(id)
    }

    /// Determine if this client's session is ready for use.
    pub async fn is_ready(&self) -> Result<bool> {
        let lock = self.session.as_ref().ok_or(Error::NoSession)?;
        let session = lock.read().await;
        Ok(session.ready())
    }

    /// Get the next request identifier.
    fn next_id(&self) -> u64 {
        self.id.fetch_add(1, Ordering::SeqCst)
    }

    /// Perform the handshake for the noise protocol.
    pub async fn handshake(&mut self) -> Result<()> {
        if let ProtocolState::Handshake(initiator) = &mut self.protocol {
            let mut message = [0u8; 1024];
            let len = initiator.write_message(&[], &mut message)?;

            let url = self.server.join("api/handshake")?;
            let id = self.next_id();
            let request = RequestMessage::new(
                Some(id),
                HANDSHAKE_INITIATE,
                (self.keypair.public_key(), len),
                Cow::Borrowed(&message),
            )?;
            let packet = Packet::new_request(request);
            let body = encode(&packet).await?;

            let (_session_id, sign_bytes, body) = body!(
                self,
                id,
                HANDSHAKE_INITIATE,
                len,
                Cow::Borrowed(&message)
            );

            let response = self.client.post(url).body(body).send().await?;

            todo!("send initiator message to the server");
        }
        Ok(())
    }

    /// Attempt to authenticate to the remote node and store
    /// the client session.
    #[deprecated(note = "use noise handshake()")]
    pub async fn authenticate(&mut self) -> Result<()> {
        let session = self.new_session().await?;
        self.session = Some(RwLock::new(session));
        Ok(())
    }

    /// Negotiate a new session.
    pub async fn new_session(&self) -> Result<ClientSession> {
        let url = self.server.join("api/session")?;

        // Offer
        let address = self.signer.address()?;
        let body =
            new_rpc_call(self.next_id(), SESSION_OFFER, address).await?;

        let response =
            self.client.post(url.clone()).body(body).send().await?;

        let (_status, result, _) = self
            .read_response::<(Uuid, [u8; 16], Vec<u8>)>(
                response.status(),
                &response.bytes().await?,
            )
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
        )
        .await?;

        let response = self.client.post(url).body(body).send().await?;

        // Check we got a success response; no error indicates success
        let (_status, result, _) = self
            .read_response::<()>(response.status(), &response.bytes().await?)
            .await?;
        result?;

        // Store the session for later requests
        session.finish(client_key);

        Ok(session)
    }

    /// Create a new account.
    pub async fn create_account(
        &self,
        vault: Vec<u8>,
    ) -> Result<MaybeRetry<Option<CommitProof>>> {
        let url = self.server.join("api/account")?;

        let id = self.next_id();
        let (session_id, sign_bytes, body) =
            body!(self, id, ACCOUNT_CREATE, (), Cow::Owned(vault));

        let signature =
            encode_signature(self.signer.sign(&sign_bytes).await?).await?;
        let response =
            self.send_request(url, session_id, signature, body).await?;

        let maybe_retry = self
            .read_encrypted_response::<CommitProof>(
                response.status(),
                &response.bytes().await?,
            )
            .await?;

        maybe_retry.map(|result, _| Ok(result.ok()))
    }

    /// List vaults for an account.
    pub async fn list_vaults(&self) -> Result<MaybeRetry<Vec<Summary>>> {
        let url = self.server.join("api/account")?;

        let id = self.next_id();
        let body = new_rpc_call(id, ACCOUNT_LIST_VAULTS, ()).await?;
        let (session_id, sign_bytes, body) =
            self.build_request(&body).await?;

        let signature =
            encode_signature(self.signer.sign(&sign_bytes).await?).await?;
        let response =
            self.send_request(url, session_id, signature, body).await?;

        let maybe_retry = self
            .read_encrypted_response::<Vec<Summary>>(
                response.status(),
                &response.bytes().await?,
            )
            .await?;

        maybe_retry.map(|result, _| Ok(result?))
    }

    /// Create a new vault on a remote node.
    pub async fn create_vault(
        &self,
        vault: Vec<u8>,
    ) -> Result<MaybeRetry<Option<CommitProof>>> {
        let url = self.server.join("api/vault")?;

        let id = self.next_id();
        let (session_id, sign_bytes, body) =
            body!(self, id, VAULT_CREATE, (), Cow::Owned(vault));

        let signature =
            encode_signature(self.signer.sign(&sign_bytes).await?).await?;
        let response =
            self.send_request(url, session_id, signature, body).await?;

        let maybe_retry = self
            .read_encrypted_response::<Option<CommitProof>>(
                response.status(),
                &response.bytes().await?,
            )
            .await?;

        maybe_retry.map(|result, _| Ok(result?))
    }

    /// Delete a vault on a remote node.
    pub async fn delete_vault(
        &self,
        vault_id: &Uuid,
    ) -> Result<MaybeRetry<Option<CommitProof>>> {
        let vault_id = *vault_id;
        let url = self.server.join("api/vault")?;

        let id = self.next_id();
        let body = new_rpc_call(id, VAULT_DELETE, vault_id).await?;
        let (session_id, sign_bytes, body) =
            self.build_request(&body).await?;

        let signature =
            encode_signature(self.signer.sign(&sign_bytes).await?).await?;
        let response =
            self.send_request(url, session_id, signature, body).await?;

        let maybe_retry = self
            .read_encrypted_response::<Option<CommitProof>>(
                response.status(),
                &response.bytes().await?,
            )
            .await?;

        maybe_retry.map(|result, _| Ok(result?))
    }

    /// Update an existing vault.
    ///
    /// This should be used when the commit tree has been
    /// rewritten, for example if the history was compacted
    /// or the password for a vault was changed.
    pub async fn save_vault(
        &self,
        vault_id: &Uuid,
        vault: Vec<u8>,
    ) -> Result<MaybeRetry<Option<CommitProof>>> {
        let vault_id = *vault_id;
        let url = self.server.join("api/vault")?;

        let id = self.next_id();
        let (session_id, sign_bytes, body) =
            body!(self, id, VAULT_SAVE, vault_id, Cow::Owned(vault));

        let signature =
            encode_signature(self.signer.sign(&sign_bytes).await?).await?;
        let response =
            self.send_request(url, session_id, signature, body).await?;

        let maybe_retry = self
            .read_encrypted_response::<Option<CommitProof>>(
                response.status(),
                &response.bytes().await?,
            )
            .await?;

        maybe_retry.map(|result, _| Ok(result?))
    }

    /// Get the event log bytes for a vault.
    /// TODO: remove the Option from the body return value???
    pub async fn load_event_log(
        &self,
        vault_id: &Uuid,
        proof: Option<CommitProof>,
    ) -> Result<MaybeRetry<(Option<CommitProof>, Option<Vec<u8>>)>> {
        let vault_id = *vault_id;
        let url = self.server.join("api/events")?;

        let id = self.next_id();
        let body =
            new_rpc_call(id, EVENT_LOG_LOAD, (vault_id, proof)).await?;
        let (session_id, sign_bytes, body) =
            self.build_request(&body).await?;

        let signature =
            encode_signature(self.signer.sign(&sign_bytes).await?).await?;
        let response =
            self.send_request(url, session_id, signature, body).await?;

        let maybe_retry = self
            .read_encrypted_response::<Option<CommitProof>>(
                response.status(),
                &response.bytes().await?,
            )
            .await?;

        maybe_retry.map(|result, body| Ok((result?, Some(body))))
    }

    /// Get the commit proof of a vault on a remote node.
    pub async fn status(
        &self,
        vault_id: &Uuid,
        proof: Option<CommitProof>,
    ) -> Result<MaybeRetry<(CommitProof, Option<CommitProof>)>> {
        let vault_id = *vault_id;
        let url = self.server.join("api/events")?;

        let id = self.next_id();
        let body =
            new_rpc_call(id, EVENT_LOG_STATUS, (vault_id, proof)).await?;
        let (session_id, sign_bytes, body) =
            self.build_request(&body).await?;

        let signature =
            encode_signature(self.signer.sign(&sign_bytes).await?).await?;
        let response =
            self.send_request(url, session_id, signature, body).await?;

        let maybe_retry = self
            .read_encrypted_response::<(CommitProof, Option<CommitProof>)>(
                response.status(),
                &response.bytes().await?,
            )
            .await?;

        maybe_retry.map(|result, _| {
            let (server_proof, match_proof) = result?;
            Ok((server_proof, match_proof))
        })
    }

    /// Apply a patch to the vault on a remote node.
    /// TODO: remove the Option from the server_proof ???
    pub async fn apply_patch(
        &self,
        vault_id: Uuid, /* WARN: must not be reference */
        proof: CommitProof,
        patch: Patch<'static>,
    ) -> Result<MaybeRetry<(Option<CommitProof>, Option<CommitProof>)>> {
        let body = encode(&patch).await?;
        let url = self.server.join("api/events")?;

        let id = self.next_id();
        let (session_id, sign_bytes, body) = body!(
            self,
            id,
            EVENT_LOG_PATCH,
            (vault_id, proof),
            Cow::Owned(body)
        );

        let signature =
            encode_signature(self.signer.sign(&sign_bytes).await?).await?;
        let response =
            self.send_request(url, session_id, signature, body).await?;

        let maybe_retry = self
            .read_encrypted_response::<(CommitProof, Option<CommitProof>)>(
                response.status(),
                &response.bytes().await?,
            )
            .await?;

        maybe_retry.map(|result, _| {
            let (server_proof, match_proof) = result?;
            Ok((Some(server_proof), match_proof))
        })
    }

    /// Replace the event log for a vault on a remote node.
    /// TODO: remove the Option from the return value ???
    pub async fn save_event_log(
        &self,
        vault_id: &Uuid,
        proof: CommitProof,
        body: Vec<u8>,
    ) -> Result<MaybeRetry<Option<CommitProof>>> {
        let vault_id = *vault_id;
        let url = self.server.join("api/events")?;

        let id = self.next_id();
        let (session_id, sign_bytes, body) = body!(
            self,
            id,
            EVENT_LOG_SAVE,
            (vault_id, proof),
            Cow::Owned(body)
        );

        let signature =
            encode_signature(self.signer.sign(&sign_bytes).await?).await?;
        let response =
            self.send_request(url, session_id, signature, body).await?;

        let maybe_retry = self
            .read_encrypted_response::<CommitProof>(
                response.status(),
                &response.bytes().await?,
            )
            .await?;

        maybe_retry.map(|result, _| Ok(Some(result?)))
    }

    /// Build an encrypted request.
    async fn build_request(
        &self,
        request: &[u8],
    ) -> Result<(Uuid, [u8; 32], Vec<u8>)> {
        //let id = self.next_id();
        let lock = self.session.as_ref().ok_or(Error::NoSession)?;
        let mut session = lock.write().await;
        session.ready().then_some(()).ok_or(Error::InvalidSession)?;

        let session_id = *session.id();

        //let request = builder(id).await?;
        let aead = session.encrypt(request).await?;
        let sign_bytes =
            session.sign_bytes::<sha3::Keccak256>(&aead.nonce)?;
        let body = encode(&aead).await?;

        Ok((session_id, sign_bytes, body))
    }

    /// Send an encrypted session request.
    async fn send_request(
        &self,
        url: Url,
        session_id: Uuid,
        signature: String,
        body: Vec<u8>,
    ) -> Result<reqwest::Response> {
        let response = self
            .client
            .post(url)
            .header(AUTHORIZATION, bearer_prefix(&signature))
            .header(X_SESSION, session_id.to_string())
            .body(body)
            .send()
            .await?;
        Ok(response)
    }

    /// Read a response that is not encrypted.
    async fn read_response<T: DeserializeOwned>(
        &self,
        status: StatusCode,
        buffer: &[u8],
    ) -> Result<(StatusCode, sos_sdk::Result<T>, Vec<u8>)> {
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        let reply: Packet<'static> = decode(buffer).await?;
        let response: ResponseMessage<'static> = reply.try_into()?;
        let (_, status, result, body) = response.take::<T>()?;
        let result = result.ok_or(Error::NoReturnValue)?;
        Ok((status, result, body))
    }

    /// Read an encrypted response to an RPC call.
    async fn read_encrypted_response<T: DeserializeOwned>(
        &self,
        http_status: StatusCode,
        buffer: &[u8],
    ) -> Result<RetryResponse<T>> {
        //) -> Result<(StatusCode, sos_sdk::Result<T>, Vec<u8>)> {
        // Unauthorized means the session could not be found
        // or has expired
        if http_status == StatusCode::UNAUTHORIZED {
            //Err(Error::NotAuthorized)
            Ok(RetryResponse::Retry(http_status))
        } else if http_status.is_success()
            || http_status == StatusCode::CONFLICT
        {
            let lock = self.session.as_ref().ok_or(Error::NoSession)?;
            let mut session = lock.write().await;
            session.ready().then_some(()).ok_or(Error::InvalidSession)?;

            let aead: AeadPack = decode(buffer).await?;
            session.set_nonce(&aead.nonce);
            let buffer = session.decrypt(&aead).await?;

            let reply: Packet<'static> = decode(&buffer).await?;
            let response: ResponseMessage<'static> = reply.try_into()?;

            // We must return the inner status code as the server mutates
            // some status codes (eg: NOT_MODIFIED -> OK) so that the client
            // will read the body of the response.
            //
            // Callers need to respond to the actual NOT_MODIFIED status.

            let (_, status, result, body) = response.take::<T>()?;
            let result = result.ok_or(Error::NoReturnValue)?;
            Ok(RetryResponse::Complete(status, result, body))
        } else {
            Err(Error::ResponseCode(http_status.into()))
        }
    }
}

/// Enumeration for a response that allows for retrying the request.
enum RetryResponse<T> {
    Retry(StatusCode),
    Complete(StatusCode, sos_sdk::Result<T>, Vec<u8>),
}

impl<T> RetryResponse<T> {
    fn map<E>(
        self,
        func: impl FnOnce(sos_sdk::Result<T>, Vec<u8>) -> Result<E>,
    ) -> Result<MaybeRetry<E>> {
        match self {
            RetryResponse::Retry(status) => Ok(MaybeRetry::Retry(status)),
            RetryResponse::Complete(status, result, body) => {
                let res = func(result, body)?;
                Ok(MaybeRetry::Complete(status, res))
            }
        }
    }
}

/// Enumeration for a mapped result that may be retried
pub enum MaybeRetry<T> {
    /// Indicates the previous request should be retried.
    Retry(StatusCode),
    /// Indicates the request was completed.
    Complete(StatusCode, T),
}

impl<T> MaybeRetry<T> {
    /// Consume self into the underlying status code.
    pub fn into_status(self) -> StatusCode {
        match self {
            MaybeRetry::Complete(status, _) => status,
            MaybeRetry::Retry(status) => status,
        }
    }

    /// Unwrap as a completed request.
    ///
    /// Panices if the request should be retried.
    pub fn unwrap(self) -> (StatusCode, T) {
        match self {
            MaybeRetry::Complete(status, result) => (status, result),
            _ => {
                panic!(
                    "unwrap called on a maybe retry that should be retried"
                );
            }
        }
    }
}
