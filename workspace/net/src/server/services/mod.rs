use axum::{
    body::Bytes,
    headers::{authorization::Bearer, Authorization},
    http::StatusCode,
};

use sos_sdk::{
    decode, encode,
    events::{AuditEvent, AuditProvider, ChangeNotification},
    mpc::channel::{decrypt_server_channel, encrypt_server_channel},
    rpc::{Packet, RequestMessage, ServerEnvelope, Service},
};
use web3_address::ethereum::Address;

use std::sync::Arc;
use tokio::sync::{RwLock, RwLockWriteGuard};
use uuid::Uuid;

use crate::server::{authenticate, State};

/// Type to represent the caller of a service request.
pub struct Caller {
    address: Address,
    #[deprecated]
    session_id: Uuid,
}

impl Caller {
    /// Get the address of the caller.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Get the session id of the caller.
    #[deprecated]
    pub fn session_id(&self) -> &Uuid {
        &self.session_id
    }
}

/// Type used for the state of private services.
pub type PrivateState = (Caller, Arc<RwLock<State>>);

/// Append to the audit log.
async fn append_audit_logs<'a>(
    writer: &mut RwLockWriteGuard<'a, State>,
    events: Vec<AuditEvent>,
) -> crate::server::Result<()> {
    writer.audit_log.append_audit_events(events).await?;
    Ok(())
}

/// Send change notifications to connected clients.
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

mod account;
mod events;
mod handshake;
mod vault;

pub use account::AccountService;
pub use events::EventLogService;
pub use handshake::HandshakeService;
pub use vault::VaultService;

/// Execute a request message in the context of a service
/// that does not require session authentication.
pub(crate) async fn public_service(
    service: impl Service<State = Arc<RwLock<State>>> + Sync + Send,
    state: Arc<RwLock<State>>,
    body: Bytes,
) -> Result<(StatusCode, Bytes), StatusCode> {
    let packet: Packet<'_> =
        decode(&body).await.map_err(|_| StatusCode::BAD_REQUEST)?;

    let request: RequestMessage<'_> = packet
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let reply = service.serve(Arc::clone(&state), request).await;

    let (_status, body) = if let Some(reply) = reply {
        let status = reply.status();
        let response = Packet::new_response(reply);
        let body = encode(&response)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        (status, Bytes::from(body))
    } else {
        // Got a notification request without a message `id`
        // so we send NO_CONTENT
        (StatusCode::NO_CONTENT, Bytes::from(vec![]))
    };

    Ok((StatusCode::OK, body))
}

/// Execute a request message in the context of a service
/// that requires session authentication.
pub(crate) async fn private_service(
    service: impl Service<State = PrivateState> + Sync + Send,
    state: Arc<RwLock<State>>,
    bearer: Authorization<Bearer>,
    body: Bytes,
) -> Result<(StatusCode, Bytes), StatusCode> {
    let (server_public_key, client_public_key, request, token) = {
        let mut writer = state.write().await;

        let message: ServerEnvelope = decode(&body)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let server_public_key = writer.keypair.public_key().to_vec();
        let client_public_key = message.public_key.clone();

        let transport = writer
            .transports
            .get_mut(&message.public_key)
            .ok_or(StatusCode::UNAUTHORIZED)?;

        transport
            .valid()
            .then_some(())
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let (encoding, body) = decrypt_server_channel(
            transport.protocol_mut(),
            message.envelope,
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        // Parse the bearer token
        let token = authenticate::bearer(bearer, &body)
            .await
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        // Decode the incoming packet and request message
        let packet: Packet<'_> =
            decode(&body).await.map_err(|_| StatusCode::BAD_REQUEST)?;
        let request: RequestMessage<'_> = packet
            .try_into()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        // Refresh the transport on activity
        transport.refresh();
        drop(writer);

        (server_public_key, client_public_key, request, token)
    };

    // Get a reply from the target service
    let owner = Caller {
        address: token.address,
        // FIXME: remove this
        session_id: Uuid::new_v4(),
    };

    tracing::debug!(method = ?request.method(), "serve");
    let reply = service.serve((owner, Arc::clone(&state)), request).await;

    let (status, body) = {
        let (status, body) = if let Some(reply) = reply {
            let mut status = reply.status();

            let response = Packet::new_response(reply);
            let body = encode(&response)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

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
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let envelope =
            encrypt_server_channel(transport.protocol_mut(), &body, false)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let message = ServerEnvelope {
            public_key: server_public_key,
            envelope,
        };

        let body = encode(&message)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        (status, body)
    };

    Ok((status, Bytes::from(body)))
}
