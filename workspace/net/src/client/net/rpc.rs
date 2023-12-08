//! Remote procedure call (RPC) client implementation.
use futures::Future;
use http::{
    header::{self, HeaderValue},
    StatusCode,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use sos_sdk::{
    commit::{CommitHash, CommitProof},
    constants::{
        ACCOUNT_CREATE, ACCOUNT_LIST_VAULTS, ACCOUNT_STATUS, EVENT_LOG_DIFF,
        EVENT_LOG_LOAD, EVENT_LOG_PATCH, EVENT_LOG_STATUS,
        HANDSHAKE_INITIATE, MIME_TYPE_RPC, VAULT_CREATE, VAULT_DELETE,
        VAULT_SAVE,
    },
    crypto::SecureAccessKey,
    decode, encode,
    signer::{ecdsa::BoxedEcdsaSigner, ed25519::BoxedEd25519Signer},
    storage::AccountStatus,
    vault::{Summary, VaultId},
};

use mpc_protocol::{
    channel::{decrypt_server_channel, encrypt_server_channel},
    snow, Keypair, ProtocolState, PATTERN,
};
//use tracing::{span, Level};

#[cfg(feature = "listen")]
use crate::events::ChangeNotification;

#[cfg(feature = "listen")]
use super::websocket::WebSocketChangeListener;

use std::{
    borrow::Cow,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tokio::sync::{Mutex, RwLock};
use url::Url;

use crate::{
    client::{Error, HostedOrigin, Result},
    events::Patch,
    rpc::{Packet, RequestMessage, ResponseMessage, ServerEnvelope},
};

#[cfg(feature = "listen")]
use crate::client::{ListenOptions, WebSocketHandle};

use super::{bearer_prefix, encode_signature, AUTHORIZATION};

/// Create an RPC call without a body.
async fn new_rpc_call<T: Serialize>(
    id: u64,
    method: &str,
    params: T,
) -> Result<Vec<u8>> {
    let request = RequestMessage::new_call(Some(id), method, params)?;
    let packet = Packet::new_request(request);
    Ok(encode(&packet).await?)
}

/// Client implementation for RPC requests.
#[derive(Clone)]
pub struct RpcClient {
    origin: HostedOrigin,
    signer: BoxedEcdsaSigner,
    device: BoxedEd25519Signer,
    keypair: Keypair,
    protocol: Arc<RwLock<Option<ProtocolState>>>,
    client: reqwest::Client,
    id: Arc<Mutex<AtomicU64>>,
}

impl RpcClient {
    /// Create a new client.
    pub fn new(
        origin: HostedOrigin,
        signer: BoxedEcdsaSigner,
        device: BoxedEd25519Signer,
        keypair: Keypair,
    ) -> Result<Self> {
        let client = reqwest::Client::new();
        let protocol = Self::new_handshake(&keypair, &origin.public_key)?;
        Ok(Self {
            origin,
            signer,
            device,
            keypair,
            protocol: Arc::new(RwLock::new(protocol)),
            client,
            id: Arc::new(Mutex::new(AtomicU64::from(1))),
        })
    }

    /// Spawn a thread that listens for changes
    /// from the remote server using a websocket
    /// that performs automatic re-connection.
    #[cfg(feature = "listen")]
    pub(crate) fn listen<F>(
        &self,
        options: ListenOptions,
        handler: impl Fn(ChangeNotification) -> F + Send + Sync + 'static,
    ) -> WebSocketHandle
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let listener = WebSocketChangeListener::new(
            self.origin.clone(),
            self.signer.clone(),
            self.device.clone(),
            options,
        );
        listener.spawn(handler)
    }

    /// Generic GET function.
    pub async fn get(url: Url) -> Result<reqwest::Response> {
        let client = reqwest::Client::new();
        Ok(client.get(url).send().await?)
    }

    /// Get the server information.
    pub async fn server_info(server: Url) -> Result<reqwest::Response> {
        let client = reqwest::Client::new();
        let url = server.join("api")?;
        Ok(client.get(url).send().await?)
    }

    /// Get the total number of websocket connections.
    pub async fn num_connections(server: &Url) -> Result<usize> {
        let client = reqwest::Client::new();
        let url = server.join("api/connections")?;
        let res = client.get(url).send().await?;
        let res = res.error_for_status()?;
        let value = res.json::<usize>().await?;
        Ok(value)
    }

    fn new_handshake(
        keypair: &Keypair,
        public_key: &[u8],
    ) -> Result<Option<ProtocolState>> {
        let initiator = snow::Builder::new(PATTERN.parse()?)
            .local_private_key(keypair.private_key())
            .remote_public_key(public_key)
            .build_initiator()?;
        let protocol = ProtocolState::Handshake(Box::new(initiator));
        Ok(Some(protocol))
    }

    /// Get the signer for this client.
    pub fn signer(&self) -> &BoxedEcdsaSigner {
        &self.signer
    }

    /// Get the URL for the remote node.
    pub fn remote(&self) -> &Url {
        &self.origin.url
    }

    /// Get the noise protocol public key for this client.
    pub fn public_key(&self) -> &[u8] {
        self.keypair.public_key()
    }

    /// Determine if the noise transport is ready.
    pub async fn is_transport_ready(&self) -> bool {
        let reader = self.protocol.read().await;
        matches!(&*reader, Some(ProtocolState::Transport(_)))
    }

    /// Get the next request identifier.
    async fn next_id(&self) -> u64 {
        let id = self.id.lock().await;
        id.fetch_add(1, Ordering::SeqCst)
    }

    /// Perform the handshake for the noise protocol.
    pub async fn handshake(&self) -> Result<()> {
        // If we are already in a transport state, discard
        // the transport and perform a new handshake
        if self.is_transport_ready().await {
            let mut writer = self.protocol.write().await;
            *writer =
                Self::new_handshake(&self.keypair, &self.origin.public_key)?;
        }

        // Prepare the handshake initiator
        let (len, body) = {
            let mut writer = self.protocol.write().await;
            if let Some(ProtocolState::Handshake(initiator)) = writer.as_mut()
            {
                let mut message = [0u8; 1024];
                let len = initiator.write_message(&[], &mut message)?;

                let url = self.origin.url.join("api/handshake")?;
                let id = self.next_id().await;
                let request = RequestMessage::new(
                    Some(id),
                    HANDSHAKE_INITIATE,
                    (self.keypair.public_key(), len),
                    Cow::Borrowed(&message),
                )?;
                let packet = Packet::new_request(request);
                let body = encode(&packet).await?;
                let response =
                    self.client.post(url).body(body).send().await?;

                let (_status, result, body) = self
                    .read_response::<usize>(
                        response.status(),
                        &response.bytes().await?,
                    )
                    .await?;
                (result?, body)
            } else {
                unreachable!();
            }
        };

        // Move into transport state
        let transport = {
            let mut writer = self.protocol.write().await;
            if let Some(ProtocolState::Handshake(mut initiator)) =
                writer.take()
            {
                let mut reply = [0u8; 1024];
                initiator.read_message(&body[..len], &mut reply)?;
                let transport = initiator.into_transport_mode()?;
                transport
            } else {
                unreachable!();
            }
        };
        let mut writer = self.protocol.write().await;
        *writer = Some(ProtocolState::Transport(transport));

        Ok(())
    }

    /// Check if we are able to handle a response status code
    /// and content type.
    async fn check_response(
        &self,
        response: reqwest::Response,
    ) -> Result<reqwest::Response> {
        let json_type = HeaderValue::from_static("application/json");
        let rpc_type = HeaderValue::from_static(MIME_TYPE_RPC);
        let status = response.status();
        let content_type = response.headers().get(&header::CONTENT_TYPE);
        match (status, content_type) {
            // OK with the correct MIME type can be handled
            // or conflict with the correct MIME type can be handled
            (StatusCode::OK, Some(content_type))
            | (StatusCode::CONFLICT, Some(content_type)) => {
                if content_type == &rpc_type {
                    Ok(response)
                } else {
                    Err(Error::ResponseCode(status))
                }
            }
            // Unauthorized responses can be retried
            // to renew the noise protocol transport
            (StatusCode::UNAUTHORIZED, None)
            | (StatusCode::UNAUTHORIZED, Some(_)) => Ok(response),
            // Otherwise exit out early
            _ => {
                if let Some(content_type) = content_type {
                    if content_type == json_type {
                        let value: Value = response.json().await?;
                        Err(Error::ResponseJson(status, value))
                    } else {
                        Err(Error::ResponseCode(status))
                    }
                } else {
                    Err(Error::ResponseCode(status))
                }
            }
        }
    }

    /// Get the account status.
    pub async fn account_status(
        &self,
    ) -> Result<MaybeRetry<Option<AccountStatus>>> {
        let url = self.origin.url.join("api/account")?;

        let id = self.next_id().await;
        let request = RequestMessage::new_call(Some(id), ACCOUNT_STATUS, ())?;
        let packet = Packet::new_request(request);
        let body = encode(&packet).await?;
        let signature =
            encode_signature(self.signer.sign(&body).await?).await?;

        let body = self.encrypt_request(&body).await?;
        let response = self.send_request(url, signature, body).await?;
        let response = self.check_response(response).await?;
        let maybe_retry = self
            .read_encrypted_response::<AccountStatus>(
                response.status(),
                &response.bytes().await?,
            )
            .await?;

        maybe_retry.map(|result, _| Ok(result.ok()))
    }

    /// Create a new account.
    pub async fn create_account(
        &self,
        vault: impl AsRef<[u8]>,
        secure_access_key: &SecureAccessKey,
    ) -> Result<MaybeRetry<Option<CommitProof>>> {
        let url = self.origin.url.join("api/account")?;

        let id = self.next_id().await;
        let request = RequestMessage::new(
            Some(id),
            ACCOUNT_CREATE,
            secure_access_key,
            Cow::Borrowed(vault.as_ref()),
        )?;
        let packet = Packet::new_request(request);
        let body = encode(&packet).await?;
        let signature =
            encode_signature(self.signer.sign(&body).await?).await?;

        let body = self.encrypt_request(&body).await?;
        let response = self.send_request(url, signature, body).await?;
        let response = self.check_response(response).await?;
        let maybe_retry = self
            .read_encrypted_response::<CommitProof>(
                response.status(),
                &response.bytes().await?,
            )
            .await?;

        maybe_retry.map(|result, _| Ok(result.ok()))
    }

    /// List folders for an account.
    pub async fn list_folders(&self) -> Result<MaybeRetry<Vec<Summary>>> {
        let url = self.origin.url.join("api/account")?;
        let id = self.next_id().await;
        let body = new_rpc_call(id, ACCOUNT_LIST_VAULTS, ()).await?;
        let signature =
            encode_signature(self.signer.sign(&body).await?).await?;
        let body = self.encrypt_request(&body).await?;
        let response = self.send_request(url, signature, body).await?;
        let response = self.check_response(response).await?;
        let maybe_retry = self
            .read_encrypted_response::<Vec<Summary>>(
                response.status(),
                &response.bytes().await?,
            )
            .await?;
        maybe_retry.map(|result, _| Ok(result?))
    }

    /// Create a new folder on a remote node.
    pub async fn create_folder(
        &self,
        vault: impl AsRef<[u8]>,
        secure_key: &SecureAccessKey,
    ) -> Result<MaybeRetry<Option<CommitProof>>> {
        let url = self.origin.url.join("api/vault")?;
        let id = self.next_id().await;
        let request = RequestMessage::new(
            Some(id),
            VAULT_CREATE,
            secure_key,
            Cow::Borrowed(vault.as_ref()),
        )?;
        let packet = Packet::new_request(request);
        let body = encode(&packet).await?;
        let signature =
            encode_signature(self.signer.sign(&body).await?).await?;
        let body = self.encrypt_request(&body).await?;
        let response = self.send_request(url, signature, body).await?;
        let response = self.check_response(response).await?;
        let maybe_retry = self
            .read_encrypted_response::<Option<CommitProof>>(
                response.status(),
                &response.bytes().await?,
            )
            .await?;
        maybe_retry.map(|result, _| Ok(result?))
    }

    /// Delete a vault on a remote node.
    pub async fn delete_folder(
        &self,
        vault_id: &VaultId,
    ) -> Result<MaybeRetry<Option<CommitProof>>> {
        let vault_id = *vault_id;
        let url = self.origin.url.join("api/vault")?;

        let id = self.next_id().await;
        let body = new_rpc_call(id, VAULT_DELETE, vault_id).await?;
        let signature =
            encode_signature(self.signer.sign(&body).await?).await?;
        let body = self.encrypt_request(&body).await?;
        let response = self.send_request(url, signature, body).await?;
        let response = self.check_response(response).await?;
        let maybe_retry = self
            .read_encrypted_response::<Option<CommitProof>>(
                response.status(),
                &response.bytes().await?,
            )
            .await?;

        maybe_retry.map(|result, _| Ok(result?))
    }

    /// Update an existing folder.
    ///
    /// This should be used when the commit tree has been
    /// rewritten, for example if the history was compacted
    /// or the password for a vault was changed.
    pub async fn update_folder(
        &self,
        vault_id: &VaultId,
        vault: impl AsRef<[u8]>,
        secure_access_key: &SecureAccessKey,
    ) -> Result<MaybeRetry<Option<CommitProof>>> {
        let vault_id = *vault_id;
        let url = self.origin.url.join("api/vault")?;
        let id = self.next_id().await;
        let request = RequestMessage::new(
            Some(id),
            VAULT_SAVE,
            (vault_id, secure_access_key),
            Cow::Borrowed(vault.as_ref()),
        )?;
        let packet = Packet::new_request(request);
        let body = encode(&packet).await?;
        let signature =
            encode_signature(self.signer.sign(&body).await?).await?;

        let body = self.encrypt_request(&body).await?;
        let response = self.send_request(url, signature, body).await?;
        let response = self.check_response(response).await?;
        let maybe_retry = self
            .read_encrypted_response::<Option<CommitProof>>(
                response.status(),
                &response.bytes().await?,
            )
            .await?;

        maybe_retry.map(|result, _| Ok(result?))
    }

    /// Get a diff of events from a remote event log.
    ///
    /// Returns the number of events in the patch and
    /// a buffer that can be decoded to a `Patch`.
    pub async fn diff(
        &self,
        vault_id: &VaultId,
        last_commit: &CommitHash,
        proof: &CommitProof,
    ) -> Result<MaybeRetry<(usize, Vec<u8>)>> {
        let url = self.origin.url.join("api/events")?;
        let id = self.next_id().await;
        let body =
            new_rpc_call(id, EVENT_LOG_DIFF, (vault_id, last_commit, proof))
                .await?;
        let signature =
            encode_signature(self.signer.sign(&body).await?).await?;
        let body = self.encrypt_request(&body).await?;
        let response = self.send_request(url, signature, body).await?;
        let response = self.check_response(response).await?;
        let maybe_retry = self
            .read_encrypted_response::<usize>(
                response.status(),
                &response.bytes().await?,
            )
            .await?;

        maybe_retry.map(|result, body| Ok((result?, body)))
    }

    /// Load a buffer of the entire event log on a remote.
    pub async fn load_events(
        &self,
        vault_id: &VaultId,
    ) -> Result<MaybeRetry<(CommitProof, Option<Vec<u8>>)>> {
        let url = self.origin.url.join("api/events")?;
        let id = self.next_id().await;
        let body = new_rpc_call(id, EVENT_LOG_LOAD, vault_id).await?;
        let signature =
            encode_signature(self.signer.sign(&body).await?).await?;
        let body = self.encrypt_request(&body).await?;
        let response = self.send_request(url, signature, body).await?;
        let response = self.check_response(response).await?;
        let maybe_retry = self
            .read_encrypted_response::<CommitProof>(
                response.status(),
                &response.bytes().await?,
            )
            .await?;

        maybe_retry.map(|result, body| Ok((result?, Some(body))))
    }

    /// Get the commit state of a folder on a remote node.
    pub async fn folder_status(
        &self,
        vault_id: &VaultId,
        proof: Option<CommitProof>,
    ) -> Result<MaybeRetry<(CommitHash, CommitProof, Option<CommitProof>)>>
    {
        let url = self.origin.url.join("api/events")?;
        let id = self.next_id().await;
        let body =
            new_rpc_call(id, EVENT_LOG_STATUS, (vault_id, proof)).await?;
        let signature =
            encode_signature(self.signer.sign(&body).await?).await?;
        let body = self.encrypt_request(&body).await?;
        let response = self.send_request(url, signature, body).await?;
        let response = self.check_response(response).await?;
        let maybe_retry = self
            .read_encrypted_response::<(CommitHash, CommitProof, Option<CommitProof>)>(
                response.status(),
                &response.bytes().await?,
            )
            .await?;

        maybe_retry.map(|result, _| {
            let (last_commit, server_proof, match_proof) = result?;
            Ok((last_commit, server_proof, match_proof))
        })
    }

    /// Apply a patch to the vault on a remote node.
    /// TODO: remove the Option from the server_proof ???
    pub async fn apply_patch(
        &self,
        vault_id: &VaultId,
        before_proof: &CommitProof,
        patch: &Patch,
    ) -> Result<MaybeRetry<(Option<CommitProof>, Option<CommitProof>)>> {
        let url = self.origin.url.join("api/events")?;

        let id = self.next_id().await;
        let body = encode(patch).await?;
        let request = RequestMessage::new(
            Some(id),
            EVENT_LOG_PATCH,
            (vault_id, before_proof),
            Cow::Owned(body),
        )?;
        let packet = Packet::new_request(request);
        let body = encode(&packet).await?;
        let signature =
            encode_signature(self.signer.sign(&body).await?).await?;

        let body = self.encrypt_request(&body).await?;
        let response = self.send_request(url, signature, body).await?;
        let response = self.check_response(response).await?;
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

    /// Build an encrypted request.
    async fn encrypt_request(&self, request: &[u8]) -> Result<Vec<u8>> {
        let mut writer = self.protocol.write().await;
        let protocol = writer.as_mut().ok_or(Error::NoSession)?;
        let envelope =
            encrypt_server_channel(protocol, request, false).await?;
        let payload = ServerEnvelope {
            public_key: self.keypair.public_key().to_vec(),
            envelope,
        };
        Ok(encode(&payload).await?)
    }

    /// Send an encrypted session request.
    async fn send_request(
        &self,
        url: Url,
        signature: String,
        body: Vec<u8>,
    ) -> Result<reqwest::Response> {
        let response = self
            .client
            .post(url)
            .header(AUTHORIZATION, bearer_prefix(&signature))
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
    ) -> Result<(StatusCode, crate::rpc::Result<T>, Vec<u8>)> {
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status))?;

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
        if http_status == StatusCode::UNAUTHORIZED {
            Ok(RetryResponse::Retry(http_status))
        } else if http_status.is_success()
            || http_status == StatusCode::CONFLICT
        {
            let buffer = self.decrypt_server_envelope(buffer).await?;
            let reply: Packet<'static> = decode(&buffer).await?;
            let response: ResponseMessage<'static> = reply.try_into()?;
            let (_, status, result, body) = response.take::<T>()?;
            let result = result.ok_or(Error::NoReturnValue)?;
            Ok(RetryResponse::Complete(status, result, body))
        } else {
            Err(Error::ResponseCode(http_status))
        }
    }

    pub(crate) async fn decrypt_server_envelope(
        &self,
        buffer: &[u8],
    ) -> Result<Vec<u8>> {
        let mut writer = self.protocol.write().await;
        let protocol = writer.as_mut().ok_or(Error::NoSession)?;
        let message: ServerEnvelope = decode(buffer).await?;
        let (encoding, buffer) =
            decrypt_server_channel(protocol, message.envelope).await?;
        assert!(matches!(encoding, mpc_protocol::Encoding::Blob));
        Ok(buffer)
    }
}

/// Enumeration for a response that allows for retrying the request.
enum RetryResponse<T> {
    Retry(StatusCode),
    Complete(StatusCode, crate::rpc::Result<T>, Vec<u8>),
}

impl<T> RetryResponse<T> {
    fn map<E>(
        self,
        func: impl FnOnce(crate::rpc::Result<T>, Vec<u8>) -> Result<E>,
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
#[derive(Debug)]
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
    /// Panics if the request should be retried.
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
