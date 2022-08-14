use axum::{
    body::Bytes,
    extract::{Extension, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::{header::HeaderMap, StatusCode},
};

//use axum_macros::debug_handler;

use sos_core::{
    address::AddressStr,
    constants::ACCOUNT_CREATE,
    crypto::AeadPack,
    decode, encode,
    events::{ChangeEvent, ChangeNotification},
    rpc::{Packet, RequestMessage, ResponseMessage, Service},
    vault::Header,
    AuditEvent,
};

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{
    server::{
        authenticate::{self},
        headers::Session,
        State,
    },
    session::EncryptedChannel,
};

use super::{
    append_audit_logs, append_audit_logs_rpc, append_commit_headers,
    send_notification,
};

/// Account management service.
///
/// * `Account.create`: Create a new account.
///
struct AccountService;

#[async_trait]
impl Service for AccountService {
    type State = (AddressStr, Arc<RwLock<State>>);

    async fn handle<'a>(
        &self,
        state: Self::State,
        request: RequestMessage<'a>,
    ) -> sos_core::Result<ResponseMessage<'a>> {
        let (address, state) = state;

        match request.method() {
            ACCOUNT_CREATE => {
                let mut writer = state.write().await;
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

                append_audit_logs_rpc(&mut writer, vec![log])
                    .await
                    .map_err(Box::from)?;
                send_notification(&mut writer, notification);

                Ok(reply)
            }
            _ => Err(sos_core::Error::Message("unknown method".to_owned())),
        }
    }
}

// Handlers for account events.
pub(crate) struct AccountHandler;
impl AccountHandler {
    pub(crate) async fn post(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(session_id): TypedHeader<Session>,
        body: Bytes,
    ) -> Result<(StatusCode, Bytes), StatusCode> {
        let reader = state.read().await;
        let session = reader
            .sessions
            .get(session_id.id())
            .ok_or(StatusCode::UNAUTHORIZED)?;
        session
            .valid()
            .then_some(())
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let address = session.identity().clone();

        let aead: AeadPack =
            decode(&body).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let body = session
            .decrypt(&aead)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        drop(reader);

        let packet: Packet<'_> =
            decode(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

        let request: RequestMessage<'_> = packet
            .try_into()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let service = AccountService {};

        let reply =
            service.serve((address, Arc::clone(&state)), request).await;

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
            .get_mut(session_id.id())
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        let aead = session
            .encrypt(&body)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let body =
            encode(&aead).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok((StatusCode::OK, Bytes::from(body)))
    }

    #[deprecated]
    /// Create a new user account.
    pub(crate) async fn put_account(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        body: Bytes,
    ) -> Result<(StatusCode, HeaderMap), StatusCode> {
        if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &body)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let mut writer = state.write().await;
                if writer.backend.account_exists(&token.address).await {
                    return Err(StatusCode::CONFLICT);
                }

                let summary = Header::read_summary_slice(&body)
                    .map_err(|_| StatusCode::BAD_REQUEST)?;

                let (sync_event, proof) = writer
                    .backend
                    .create_account(&token.address, summary.id(), &body)
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                let mut headers = HeaderMap::new();
                append_commit_headers(&mut headers, &proof)?;

                let notification = ChangeNotification::new(
                    &token.address,
                    summary.id(),
                    proof,
                    vec![ChangeEvent::CreateVault],
                );

                let log = AuditEvent::from_sync_event(
                    &sync_event,
                    token.address,
                    *summary.id(),
                );

                append_audit_logs(&mut writer, vec![log]).await?;
                send_notification(&mut writer, notification);

                Ok((StatusCode::OK, headers))
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
