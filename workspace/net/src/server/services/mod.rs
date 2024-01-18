use axum::{
    body::Bytes,
    http::{
        header::{self, HeaderMap, HeaderValue},
        StatusCode,
    },
};
use axum_extra::headers::{authorization::Bearer, Authorization};

use async_trait::async_trait;
use sos_sdk::{
    constants::MIME_TYPE_RPC, decode, encode, signer::ecdsa::Address,
};

use std::sync::Arc;

use crate::{
    rpc::{Packet, RequestMessage, ResponseMessage},
    server::{
        authenticate::{self, BearerToken},
        handlers::{service::ServiceQuery, websocket::BroadcastMessage},
        Error, Result, ServerBackend, ServerState, State,
    },
};

#[cfg(feature = "listen")]
use crate::events::ChangeNotification;

//mod account;
mod sync;

//pub use account::AccountService;
pub use sync::SyncService;

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
    token: BearerToken,
    connection_id: String,
}

impl Caller {
    /// Account address of the caller.
    pub fn address(&self) -> &Address {
        &self.token.address
    }

    /// Connection identifier.
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }
}

/// Type used for the state of private services.
pub type PrivateState = (Caller, (ServerState, ServerBackend));

/// Send change notifications to connected clients.
#[cfg(feature = "listen")]
fn send_notification(
    writer: &mut State,
    caller: &Caller,
    notification: ChangeNotification,
) {
    // Send notification on the websockets channel
    match serde_json::to_vec(&notification) {
        Ok(buffer) => {
            if let Some(conn) = writer.sockets.get(caller.address()) {
                let message = BroadcastMessage {
                    buffer,
                    connection_id: caller.connection_id().to_owned(),
                };
                if conn.tx.send(message).is_err() {
                    tracing::debug!("websocket events channel dropped");
                }
            }
        }
        Err(e) => {
            tracing::error!("{}", e);
        }
    }
}

/// Execute a request message in the context of a service
/// that requires session authentication.
pub(crate) async fn private_service(
    service: impl Service<State = PrivateState> + Sync + Send,
    state: ServerState,
    backend: ServerBackend,
    bearer: Authorization<Bearer>,
    query: ServiceQuery,
    body: Bytes,
    restricted: bool,
) -> Result<(StatusCode, HeaderMap, Bytes)> {
    let mut headers = HeaderMap::new();

    let (request, token, message_body) = {
        // Parse the bearer token
        let token = authenticate::bearer(bearer, &body)
            .await
            .map_err(|_| Error::BadRequest)?;

        // Decode the incoming packet and request message
        let packet: Packet<'_> =
            decode(&body).await.map_err(|_| Error::BadRequest)?;
        let request: RequestMessage<'_> = packet.try_into()?;

        (request, token, body)
    };

    // Restricted services require a device signature
    match (restricted, &token.device_signature) {
        (true, None) => {
            return Err(Error::Forbidden);
        }
        (true, Some(device_signature)) => {
            let reader = backend.read().await;
            reader
                .verify_device(
                    &token.address,
                    device_signature,
                    &message_body,
                )
                .await?;
        }
        _ => {}
    }

    // Call the target service for a reply
    let owner = Caller {
        token,
        connection_id: query.connection_id,
    };

    // Deny unauthorized account addresses
    {
        let reader = state.read().await;
        if !reader.config.access.is_allowed_access(owner.address()) {
            return Err(Error::Forbidden);
        }
    }

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

        (status, body)
    };

    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(MIME_TYPE_RPC),
    );

    Ok((status, headers, Bytes::from(body)))
}
