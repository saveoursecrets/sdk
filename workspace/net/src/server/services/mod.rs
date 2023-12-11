use axum::{
    body::Bytes,
    headers::{authorization::Bearer, Authorization},
    http::{
        header::{self, HeaderMap, HeaderValue},
        StatusCode,
    },
};

use async_trait::async_trait;
use mpc_protocol::channel::{decrypt_server_channel, encrypt_server_channel};
use sos_sdk::{constants::MIME_TYPE_RPC, decode, encode};
use web3_address::ethereum::Address;

use std::sync::Arc;
use tokio::sync::RwLockWriteGuard;

use crate::{
    rpc::{Packet, RequestMessage, ResponseMessage, ServerEnvelope},
    server::{
        authenticate, Error, Result, ServerBackend, ServerState, State,
    },
};

#[cfg(feature = "listen")]
use crate::events::ChangeNotification;

mod account;
mod device;
mod events;
mod handshake;
mod identity;
mod vault;

pub use account::AccountService;
pub use device::DeviceService;
pub use events::EventLogService;
pub use handshake::HandshakeService;
pub use identity::IdentityService;
pub use vault::VaultService;

/// Trait for implementations that process incoming requests.
#[async_trait]
pub trait Service {
    /// State for this service.
    type State: Send + Sync;

    /// Handle an incoming message.
    async fn handle<'a>(
        &self,
        state: Self::State,
        request: RequestMessage<'a>,
    ) -> Result<ResponseMessage<'a>>;

    /// Serve an incoming request.
    async fn serve<'a>(
        &self,
        state: Self::State,
        request: RequestMessage<'a>,
    ) -> Option<ResponseMessage<'a>> {
        match self.handle(state, request).await {
            Ok(res) => {
                if res.id().is_some() {
                    Some(res)
                } else {
                    None
                }
            }
            Err(e) => {
                let reply: ResponseMessage<'_> = e.into();
                Some(reply)
            }
        }
    }
}

/// Type to represent the caller of a service request.
pub struct Caller {
    address: Address,
    public_key: Vec<u8>,
}

impl Caller {
    /// Get the address of the caller.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Get the public key of the caller.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

/// Type used for the state of private services.
pub type PrivateState = (Caller, (ServerState, ServerBackend));

/// Send change notifications to connected clients.
#[cfg(feature = "listen")]
fn send_notification(
    writer: &mut RwLockWriteGuard<'_, State>,
    _caller: &Caller,
    notification: ChangeNotification,
) {
    // Changes can be empty for non-mutating sync events
    // that correspond to audit logs; for example, reading secrets
    if !notification.changes().is_empty() {
        // Send notification on the websockets channel
        match serde_json::to_vec(&notification) {
            Ok(buffer) => {
                if let Some(conn) = writer.sockets.get(notification.address())
                {
                    if conn.tx.send(buffer).is_err() {
                        tracing::debug!("websocket events channel dropped");
                    }
                }
            }
            Err(e) => {
                tracing::error!("{}", e);
            }
        }
    }
}

/// Execute a request message in the context of a service
/// that does not require session authentication.
pub(crate) async fn public_service(
    service: impl Service<State = ServerState> + Sync + Send,
    state: ServerState,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Bytes)> {
    let mut headers = HeaderMap::new();

    let packet: Packet<'_> =
        decode(&body).await.map_err(|_| Error::BadRequest)?;

    let request: RequestMessage<'_> = packet.try_into()?;

    let reply = service.serve(Arc::clone(&state), request).await;

    let (_status, body) = if let Some(reply) = reply {
        let status = reply.status();
        let response = Packet::new_response(reply);
        let body = encode(&response).await?;
        (status, Bytes::from(body))
    } else {
        // Got a notification request without a message `id`
        // so we send NO_CONTENT
        (StatusCode::NO_CONTENT, Bytes::from(vec![]))
    };

    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(MIME_TYPE_RPC),
    );

    Ok((StatusCode::OK, headers, body))
}

/// Execute a request message in the context of a service
/// that requires session authentication.
pub(crate) async fn private_service(
    service: impl Service<State = PrivateState> + Sync + Send,
    state: ServerState,
    backend: ServerBackend,
    bearer: Authorization<Bearer>,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Bytes)> {
    let mut headers = HeaderMap::new();

    let (server_public_key, client_public_key, request, token) = {
        let mut writer = state.write().await;
        let message: ServerEnvelope = decode(&body).await?;

        let server_public_key = writer.keypair.public_key().to_vec();
        let client_public_key = message.public_key.clone();
        let transport = writer
            .transports
            .get_mut(&message.public_key)
            .ok_or(Error::Unauthorized)?;

        transport.valid().then_some(()).ok_or(Error::Unauthorized)?;

        let (encoding, body) = decrypt_server_channel(
            transport.protocol_mut(),
            message.envelope,
        )
        .await?;

        assert!(matches!(encoding, mpc_protocol::Encoding::Blob));

        // Parse the bearer token
        let token = authenticate::bearer(bearer, &body)
            .await
            .map_err(|_| Error::BadRequest)?;

        // Decode the incoming packet and request message
        let packet: Packet<'_> =
            decode(&body).await.map_err(|_| Error::BadRequest)?;
        let request: RequestMessage<'_> = packet.try_into()?;

        // Refresh the transport on activity
        transport.refresh();

        (server_public_key, client_public_key, request, token)
    };

    // Get a reply from the target service
    let owner = Caller {
        address: token.address,
        public_key: client_public_key.clone(),
    };

    tracing::debug!(method = ?request.method(), "serve");
    let reply = service
        .serve((owner, (Arc::clone(&state), Arc::clone(&backend))), request)
        .await;

    let (status, body) = {
        let (status, body) = if let Some(reply) = reply {
            let mut status = reply.status();

            let response = Packet::new_response(reply);
            let body = encode(&response).await?;

            // If we send an actual NOT_MODIFIED response then the
            // client will not receive any body content so we have
            // to mutate the actual HTTP response and let the client
            // act on the inner status code
            if status == StatusCode::NOT_MODIFIED {
                status = StatusCode::OK;
            }

            (status, body)
        } else {
            // Got a notification request without a message `id`
            // so we send NO_CONTENT
            (StatusCode::NO_CONTENT, vec![])
        };

        let mut writer = state.write().await;
        let transport = writer
            .transports
            .get_mut(&client_public_key)
            .ok_or(Error::Unauthorized)?;

        let envelope =
            encrypt_server_channel(transport.protocol_mut(), &body, false)
                .await?;

        let message = ServerEnvelope {
            public_key: server_public_key,
            envelope,
        };

        let body = encode(&message).await?;

        (status, body)
    };

    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(MIME_TYPE_RPC),
    );

    Ok((status, headers, Bytes::from(body)))
}
