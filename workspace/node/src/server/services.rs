use axum::{body::Bytes, http::StatusCode};

use sos_core::{
    address::AddressStr,
    constants::{
        ACCOUNT_CREATE, ACCOUNT_LIST_VAULTS, SESSION_OFFER, SESSION_VERIFY,
    },
    crypto::AeadPack,
    decode, encode,
    events::{ChangeEvent, ChangeNotification, EventKind},
    rpc::{Packet, RequestMessage, ResponseMessage, Service},
    vault::Header,
    AuditEvent, AuditProvider,
};

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::{RwLock, RwLockWriteGuard};
use uuid::Uuid;
use web3_signature::Signature;

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

/// Session negotiation service.
///
/// * `Session.offer`: Create a session offer.
/// * `Session.verify`: Verify client identity.
///
pub struct SessionService;

#[async_trait]
impl Service for SessionService {
    type State = Arc<RwLock<State>>;

    async fn handle<'a>(
        &self,
        state: Self::State,
        request: RequestMessage<'a>,
    ) -> sos_core::Result<ResponseMessage<'a>> {
        match request.method() {
            SESSION_OFFER => {
                let mut writer = state.write().await;
                let address = request.parameters::<AddressStr>()?;
                let (session_id, server_session) =
                    writer.sessions.offer(address);

                let value = (
                    session_id,
                    server_session.challenge(),
                    server_session.public_key(),
                );

                let reply: ResponseMessage<'_> =
                    (request.id(), value).try_into()?;
                Ok(reply)
            }
            SESSION_VERIFY => {
                let (session_id, signature, public_key) =
                    request.parameters::<(Uuid, Signature, Vec<u8>)>()?;

                let mut writer = state.write().await;
                let session = writer
                    .sessions
                    .verify_identity(&session_id, signature)
                    .map_err(Box::from)?;
                session.compute_ecdh(&public_key).map_err(Box::from)?;

                let reply: ResponseMessage<'_> =
                    (request.id(), ()).try_into()?;
                Ok(reply)
            }
            _ => Err(sos_core::Error::Message("unknown method".to_owned())),
        }
    }
}

/// Account management service.
///
/// * `Account.create`: Create a new account.
/// * `Account.list_vaults`: List vault summaries for an account.
///
pub struct AccountService;

#[async_trait]
impl Service for AccountService {
    type State = (AddressStr, Arc<RwLock<State>>);

    async fn handle<'a>(
        &self,
        state: Self::State,
        request: RequestMessage<'a>,
    ) -> sos_core::Result<ResponseMessage<'a>> {
        let (address, state) = state;

        let mut writer = state.write().await;

        match request.method() {
            ACCOUNT_CREATE => {
                if writer.backend.account_exists(&address).await {
                    return Ok((StatusCode::CONFLICT, request.id()).into());
                }

                let summary = Header::read_summary_slice(request.body())?;

                let (sync_event, proof) = writer
                    .backend
                    .create_account(&address, summary.id(), request.body())
                    .await
                    .map_err(Box::from)?;

                let reply: ResponseMessage<'_> =
                    (request.id(), &proof).try_into()?;

                let notification = ChangeNotification::new(
                    &address,
                    summary.id(),
                    proof,
                    vec![ChangeEvent::CreateVault],
                );

                let log = AuditEvent::from_sync_event(
                    &sync_event,
                    address,
                    *summary.id(),
                );

                append_audit_logs(&mut writer, vec![log])
                    .await
                    .map_err(Box::from)?;
                send_notification(&mut writer, notification);

                Ok(reply)
            }
            ACCOUNT_LIST_VAULTS => {
                if !writer.backend.account_exists(&address).await {
                    return Ok((StatusCode::NOT_FOUND, request.id()).into());
                }

                let summaries =
                    writer.backend.list(&address).await.map_err(Box::from)?;

                let reply: ResponseMessage<'_> =
                    (request.id(), summaries).try_into()?;

                let log =
                    AuditEvent::new(EventKind::LoginResponse, address, None);
                append_audit_logs(&mut writer, vec![log])
                    .await
                    .map_err(Box::from)?;

                Ok(reply)
            }
            _ => Err(sos_core::Error::Message("unknown method".to_owned())),
        }
    }
}

/// Vault management service.
///
/// * `Vault.create`: Create a new vault.
///
pub struct VaultService;

#[async_trait]
impl Service for VaultService {
    type State = (AddressStr, Arc<RwLock<State>>);

    async fn handle<'a>(
        &self,
        state: Self::State,
        request: RequestMessage<'a>,
    ) -> sos_core::Result<ResponseMessage<'a>> {
        let (address, state) = state;

        match request.method() {
            VAULT_CREATE => {
                // Check it looks like a vault payload
                let summary = Header::read_summary_slice(request.body())?;

                let reader = state.read().await;
                let (exists, proof) = reader
                    .backend
                    .wal_exists(&address, summary.id())
                    .await
                    .map_err(Box::from)?;
                drop(reader);

                if exists {
                    // Send commit proof back with conflict response
                    Ok((StatusCode::CONFLICT, request.id(), proof)
                        .try_into()?)
                } else {
                    let mut writer = state.write().await;
                    let (sync_event, proof) = writer
                        .backend
                        .create_wal(&address, summary.id(), request.body())
                        .await
                        .map_err(Box::from)?;

                    let reply: ResponseMessage<'_> =
                        (request.id(), Some(&proof)).try_into()?;

                    let notification = ChangeNotification::new(
                        &address,
                        summary.id(),
                        proof,
                        vec![ChangeEvent::CreateVault],
                    );

                    let log = AuditEvent::from_sync_event(
                        &sync_event,
                        address,
                        *summary.id(),
                    );

                    append_audit_logs(&mut writer, vec![log])
                        .await
                        .map_err(Box::from)?;
                    send_notification(&mut writer, notification);

                    Ok(reply)
                }
            }
            _ => Err(sos_core::Error::Message("unknown method".to_owned())),
        }
    }
}

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

    let body = if let Some(reply) = reply {
        let response = Packet::new_response(reply);
        let body = encode(&response)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Bytes::from(body)
    } else {
        Bytes::from(vec![])
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

    let body = if let Some(reply) = reply {
        let response = Packet::new_response(reply);
        let body = encode(&response)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        body
    } else {
        vec![]
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
    Ok((StatusCode::OK, Bytes::from(body)))
}
