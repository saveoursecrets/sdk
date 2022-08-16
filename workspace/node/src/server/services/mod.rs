use axum::{
    body::Bytes,
    headers::{authorization::Bearer, Authorization},
    http::StatusCode,
};

use sos_core::{
    address::AddressStr,
    crypto::AeadPack,
    decode, encode,
    events::ChangeNotification,
    rpc::{Packet, RequestMessage, Service},
    AuditEvent, AuditProvider,
};

use std::sync::Arc;
use tokio::sync::{RwLock, RwLockWriteGuard};
use uuid::Uuid;

use crate::{
    server::{authenticate, State},
    session::EncryptedChannel,
};

/// Append to the audit log.
async fn append_audit_logs<'a>(
    writer: &mut RwLockWriteGuard<'a, State>,
    events: Vec<AuditEvent>,
) -> crate::server::Result<()> {
    writer.audit_log.append_audit_events(&events).await?;
    Ok(())
}

/// Send change notifications to connected clients.
fn send_notification<'a>(
    writer: &mut RwLockWriteGuard<'a, State>,
    notification: ChangeNotification,
) {
    // Changes can be empty for non-mutating sync events
    // that correspond to audit logs; for example, reading secrets
    if !notification.changes().is_empty() {
        // Send notification on the SSE channel
        if let Some(conn) = writer.sockets.get(notification.address()) {
            if let Err(_) = conn.tx.send(notification) {
                tracing::debug!("server sent events channel dropped");
            }
        }
    }
}

mod account;
mod session;
mod vault;
mod wal;

pub use account::AccountService;
pub use session::SessionService;
pub use vault::VaultService;
pub use wal::WalService;

/// Execute a request message in the context of a service
/// that does not require session authentication.
pub(crate) async fn public_service(
    service: impl Service<State = Arc<RwLock<State>>> + Sync + Send,
    state: Arc<RwLock<State>>,
    body: Bytes,
) -> Result<(StatusCode, Bytes), StatusCode> {
    let packet: Packet<'_> =
        decode(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    let request: RequestMessage<'_> = packet
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let reply = service.serve(Arc::clone(&state), request).await;

    let (_status, body) = if let Some(reply) = reply {
        let status = reply.status();
        let response = Packet::new_response(reply);
        let body = encode(&response)
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
    service: impl Service<State = (AddressStr, Arc<RwLock<State>>)> + Sync + Send,
    state: Arc<RwLock<State>>,
    bearer: Authorization<Bearer>,
    session_id: &Uuid,
    body: Bytes,
) -> Result<(StatusCode, Bytes), StatusCode> {
    let mut writer = state.write().await;
    let session = writer
        .sessions
        .get_mut(session_id)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    session
        .valid()
        .then_some(())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let address = session.identity().clone();

    let aead: AeadPack =
        decode(&body).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Verify the nonce is ahead of this nonce
    // otherwise we may have a possible replay attack
    session
        .verify_nonce(&aead.nonce)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Verify the signature for the message
    let sign_bytes = session
        .sign_bytes::<sha3::Keccak256>(&aead.nonce)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Parse the bearer token
    let token = authenticate::bearer(bearer, &sign_bytes)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Attempt to impersonate the session identity
    if &token.address != session.identity() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Decrypt the incoming data ensuring we update
    // our session nonce for any reply
    session.set_nonce(&aead.nonce);
    let body = session
        .decrypt(&aead)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Decode the incoming packet and request message
    let packet: Packet<'_> =
        decode(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let request: RequestMessage<'_> = packet
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Refresh the session on activity
    session.refresh();
    drop(writer);

    // Get a reply from the target service
    let reply = service.serve((address, Arc::clone(&state)), request).await;

    let (status, body) = if let Some(reply) = reply {
        let mut status = reply.status();

        let response = Packet::new_response(reply);
        let body = encode(&response)
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
    let session = writer
        .sessions
        .get_mut(session_id)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let aead = session
        .encrypt(&body)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let body =
        encode(&aead).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((status, Bytes::from(body)))
}
