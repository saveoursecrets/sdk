//! Handlers and service for session authentication.
use axum::{
    body::Bytes,
    extract::{Extension, Path, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::{header::HeaderMap, StatusCode},
};

use async_trait::async_trait;
use std::sync::{Arc, RwLock};

use sos_core::{
    address::AddressStr,
    decode, encode,
    rpc::{Packet, RequestMessage, ResponseMessage, Service},
};
use uuid::Uuid;
use web3_signature::Signature;

use crate::server::State;

/// Session negotiation service.
///
/// * `Session.offer`: Create a session offer.
/// * `Session.verify`: Verify client identity.
///
struct SessionService {}

#[async_trait]
impl Service for SessionService {
    type State = Arc<RwLock<State>>;

    fn handle<'a>(
        &self,
        state: &Self::State,
        request: RequestMessage<'a>,
    ) -> sos_core::Result<Option<ResponseMessage<'a>>> {
        match request.method() {
            "Session.offer" => {
                let mut writer = state.write().unwrap();
                let address = request.parameters::<AddressStr>()?;
                let (session_id, server_session) =
                    writer.sessions.offer(address);

                let value = (
                    session_id,
                    server_session.challenge(),
                    server_session.public_key(),
                );

                let reply: ResponseMessage<'_> =
                    (request, value).try_into()?;
                Ok(Some(reply))
            }
            "Session.verify" => {
                let (session_id, signature, public_key) =
                    request.parameters::<(Uuid, Signature, Vec<u8>)>()?;

                let mut writer = state.write().unwrap();
                let session = writer
                    .sessions
                    .verify_identity(&session_id, signature)
                    .map_err(Box::from)?;
                session.compute_ecdh(&public_key).map_err(Box::from)?;

                let reply: ResponseMessage<'_> = (request, ()).try_into()?;
                Ok(Some(reply))
            }
            _ => Err(sos_core::Error::Message("unknown method".to_owned())),
        }
    }
}

pub(crate) struct SessionHandler;
impl SessionHandler {
    /// Entry point for the session service.
    pub(crate) async fn post(
        Extension(state): Extension<Arc<RwLock<State>>>,
        body: Bytes,
    ) -> Result<(StatusCode, Bytes), StatusCode> {
        let packet: Packet<'_> =
            decode(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

        let request: RequestMessage<'_> = packet
            .try_into()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let service = SessionService {};

        let reply = service
            .handle(&state, request)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

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
}
