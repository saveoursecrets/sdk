use axum::{body::Bytes, http::StatusCode};

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

use crate::{server::State, session::EncryptedChannel};

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
        if let Some(conn) = writer.sse.get(notification.address()) {
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

    let (status, body) = if let Some(reply) = reply {
        //let status = reply.status();
        let response = Packet::new_response(reply);
        let body = encode(&response)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        (StatusCode::OK, Bytes::from(body))
    } else {
        // FIXME: use NO_CONTENT ???
        (StatusCode::OK, Bytes::from(vec![]))
    };

    Ok((StatusCode::OK, body))
}

/// Execute a request message in the context of a service
/// that requires session authentication.
pub(crate) async fn private_service(
    service: impl Service<State = (AddressStr, Arc<RwLock<State>>)> + Sync + Send,
    state: Arc<RwLock<State>>,
    session_id: &Uuid,
    body: Bytes,
) -> Result<(StatusCode, Bytes), StatusCode> {
    let reader = state.read().await;
    let session = reader
        .sessions
        .get(session_id)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    session
        .valid()
        .then_some(())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let address = session.identity().clone();

    let aead: AeadPack =
        decode(&body).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // FIXME: check nonce is not equal to or behind last used nonce

    let body = session
        .decrypt(&aead)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    drop(reader);

    let packet: Packet<'_> =
        decode(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    let request: RequestMessage<'_> = packet
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let reply = service.serve((address, Arc::clone(&state)), request).await;

    let (status, body) = if let Some(reply) = reply {
        //let status = reply.status();
        let response = Packet::new_response(reply);
        let body = encode(&response)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        (StatusCode::OK, body)
    } else {
        // FIXME: use NO_CONTENT ???
        (StatusCode::OK, vec![])
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
