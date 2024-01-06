//! Remote procedure call (RPC) client implementation.
use async_trait::async_trait;
use futures::Future;
use http::{
    header::{self, HeaderValue},
    StatusCode,
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use sos_sdk::{
    constants::{
        ACCOUNT_CREATE, HANDSHAKE_INITIATE, MIME_TYPE_RPC, SYNC_RESOLVE,
        SYNC_STATUS,
    },
    decode, encode,
    signer::{ecdsa::BoxedEcdsaSigner, ed25519::BoxedEd25519Signer},
    sync::{ChangeSet, Client, SyncDiff, SyncStatus},
};

use http::header::AUTHORIZATION;
use mpc_protocol::{
    channel::{decrypt_server_channel, encrypt_server_channel},
    snow, Keypair, ProtocolState, PATTERN,
};
use tracing::{span, Level};

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
    rpc::{Packet, RequestMessage, ResponseMessage, ServerEnvelope},
};

#[cfg(feature = "listen")]
use crate::client::{ListenOptions, WebSocketHandle};

use super::{
    bearer_prefix, encode_account_signature, encode_device_signature,
};

/// Retry a request after renewing a session if an
/// UNAUTHORIZED response is returned.
#[doc(hidden)]
macro_rules! retry {
    ($future:expr, $client:expr) => {{
        let future = $future();
        let maybe_retry = future.await?;

        match maybe_retry {
            MaybeRetry::Retry(status) => {
                if status == StatusCode::UNAUTHORIZED
                    && $client.is_transport_ready().await
                {
                    tracing::debug!("renew client session");
                    $client.handshake().await?;
                    let future = $future();
                    let maybe_retry = future.await?;
                    match maybe_retry {
                        MaybeRetry::Retry(status) => {
                            if status == StatusCode::UNAUTHORIZED {
                                return Err(Error::NotAuthorized);
                            } else {
                                return Err(Error::ResponseCode(status));
                            }
                        }
                        MaybeRetry::Complete(status, result) => {
                            (status, result)
                        }
                    }
                } else {
                    return Err(Error::NotAuthorized);
                }
            }
            MaybeRetry::Complete(status, result) => (status, result),
        }
    }};
}

/// Result for a request that may be retried.
#[derive(Debug)]
enum MaybeRetry<T> {
    /// Indicates the previous request should be retried.
    Retry(StatusCode),
    /// Indicates the request was completed.
    Complete(StatusCode, T),
}

/// Response that may retry the request.
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

/// Client for the self-hosted server that
/// communicates using RPC messages.
#[derive(Clone)]
pub struct RpcClient {
    origin: HostedOrigin,
    account_signer: BoxedEcdsaSigner,
    device_signer: BoxedEd25519Signer,
    keypair: Keypair,
    protocol: Arc<RwLock<Option<ProtocolState>>>,
    client: reqwest::Client,
    id: Arc<Mutex<AtomicU64>>,
    connection_id: String,
}

impl RpcClient {
    /// Create a new client.
    pub fn new(
        origin: HostedOrigin,
        account_signer: BoxedEcdsaSigner,
        device_signer: BoxedEd25519Signer,
        keypair: Keypair,
        connection_id: String,
    ) -> Result<Self> {
        let client = reqwest::Client::new();
        let protocol = Self::new_handshake(&keypair, &origin.public_key)?;
        Ok(Self {
            origin,
            account_signer,
            device_signer,
            keypair,
            protocol: Arc::new(RwLock::new(protocol)),
            client,
            id: Arc::new(Mutex::new(AtomicU64::from(1))),
            connection_id,
        })
    }

    /// Account signing key.
    pub fn account_signer(&self) -> &BoxedEcdsaSigner {
        &self.account_signer
    }

    /// Device signing key.
    pub fn device_signer(&self) -> &BoxedEd25519Signer {
        &self.device_signer
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
            self.account_signer.clone(),
            self.device_signer.clone(),
            options,
        );
        listener.spawn(handler)
    }

    /// Generic GET function.
    pub async fn get(url: Url) -> Result<reqwest::Response> {
        let client = reqwest::Client::new();
        Ok(client.get(url).send().await?)
    }

    /// Server information.
    pub async fn server_info(server: Url) -> Result<reqwest::Response> {
        let client = reqwest::Client::new();
        let url = server.join("api")?;
        Ok(client.get(url).send().await?)
    }

    /// Total number of websocket connections on remote.
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

    /// Noise protocol public key for this client.
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

    /// Build a URL including the connection identifier
    /// in the query string.
    fn build_url(&self, route: &str) -> Result<Url> {
        let mut url = self.origin.url.join(route)?;
        url.query_pairs_mut()
            .append_pair("connection_id", &self.connection_id);
        Ok(url)
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

    /// Try to create a new account.
    async fn try_create_account(
        &self,
        account: &ChangeSet,
    ) -> Result<MaybeRetry<Option<()>>> {
        let url = self.build_url("api/account")?;

        let id = self.next_id().await;
        let body = encode(account).await?;
        let request = RequestMessage::new(
            Some(id),
            ACCOUNT_CREATE,
            (),
            Cow::Owned(body),
        )?;
        let packet = Packet::new_request(request);
        let body = encode(&packet).await?;
        let account_signature =
            encode_account_signature(self.account_signer.sign(&body).await?)
                .await?;

        let body = self.encrypt_request(&body).await?;
        let response = self
            .send_request(url, body, account_signature, None)
            .await?;
        let response = self.check_response(response).await?;
        let maybe_retry = self
            .read_encrypted_response::<()>(
                response.status(),
                &response.bytes().await?,
            )
            .await?;

        maybe_retry.map(|result, _| Ok(result.ok()))
    }

    /// Try to sync status on remote.
    async fn try_sync_status(
        &self,
    ) -> Result<MaybeRetry<Option<SyncStatus>>> {
        let url = self.build_url("api/account")?;

        let id = self.next_id().await;
        let request = RequestMessage::new_call(Some(id), SYNC_STATUS, ())?;
        let packet = Packet::new_request(request);
        let body = encode(&packet).await?;
        let account_signature =
            encode_account_signature(self.account_signer.sign(&body).await?)
                .await?;
        let device_signature =
            encode_device_signature(self.device_signer.sign(&body).await?)
                .await?;

        let body = self.encrypt_request(&body).await?;
        let response = self
            .send_request(
                url,
                body,
                account_signature,
                Some(device_signature),
            )
            .await?;
        let response = self.check_response(response).await?;
        let maybe_retry = self
            .read_encrypted_response::<Option<SyncStatus>>(
                response.status(),
                &response.bytes().await?,
            )
            .await?;

        maybe_retry.map(|result, _| Ok(result?))
    }

    /// Try to sync with a remote.
    async fn try_sync(
        &self,
        local_status: &SyncStatus,
        diff: &SyncDiff,
    ) -> Result<MaybeRetry<Vec<u8>>> {
        let url = self.build_url("api/sync")?;

        let id = self.next_id().await;
        let body = encode(diff).await?;
        let request = RequestMessage::new(
            Some(id),
            SYNC_RESOLVE,
            &local_status,
            Cow::Owned(body),
        )?;

        let packet = Packet::new_request(request);
        let body = encode(&packet).await?;
        let account_signature =
            encode_account_signature(self.account_signer.sign(&body).await?)
                .await?;
        let device_signature =
            encode_device_signature(self.device_signer.sign(&body).await?)
                .await?;

        let body = self.encrypt_request(&body).await?;
        let response = self
            .send_request(
                url,
                body,
                account_signature,
                Some(device_signature),
            )
            .await?;
        let response = self.check_response(response).await?;
        let maybe_retry = self
            .read_encrypted_response::<SyncStatus>(
                response.status(),
                &response.bytes().await?,
            )
            .await?;

        maybe_retry.map(|_, body| Ok(body))
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
        body: Vec<u8>,
        account_signature: String,
        device_signature: Option<String>,
    ) -> Result<reqwest::Response> {
        let auth = if let Some(device_signature) = &device_signature {
            bearer_prefix(&account_signature, Some(device_signature))
        } else {
            bearer_prefix(&account_signature, None)
        };
        let response = self
            .client
            .post(url)
            .header(AUTHORIZATION, auth)
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

#[async_trait]
impl Client for RpcClient {
    type Error = Error;

    fn url(&self) -> &Url {
        &self.origin.url
    }

    async fn create_account(&self, account: &ChangeSet) -> Result<()> {
        let span = span!(Level::DEBUG, "create_account");
        let _enter = span.enter();

        let (status, _) = retry!(|| self.try_create_account(account), self);

        tracing::debug!(status = %status);

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status))?;
        Ok(())
    }

    async fn sync_status(&self) -> Result<Option<SyncStatus>> {
        let (_, value) = retry!(|| self.try_sync_status(), self);
        Ok(value)
    }

    async fn sync(
        &self,
        local_status: &SyncStatus,
        diff: &SyncDiff,
    ) -> std::result::Result<SyncDiff, Self::Error> {
        let (status, body) =
            retry!(|| self.try_sync(local_status, diff), self);

        tracing::debug!(status = %status);

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status))?;

        Ok(decode(&body).await?)
    }
}
