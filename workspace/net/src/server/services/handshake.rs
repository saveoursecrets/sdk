use sos_sdk::{
    constants::HANDSHAKE_INITIATE,
    mpc::{snow, PATTERN},
    rpc::{RequestMessage, ResponseMessage, Service},
};

use axum::http::StatusCode;
use async_trait::async_trait;
use std::{sync::Arc, borrow::Cow};
use tokio::sync::RwLock;
use uuid::Uuid;
use web3_signature::Signature;
use crate::server::State;

/// Handshake service.
///
/// * `Handshake.initiate`: Client handshake initiation.
///
pub struct HandshakeService;

#[async_trait]
impl Service for HandshakeService {
    type State = Arc<RwLock<State>>;

    async fn handle<'a>(
        &self,
        state: Self::State,
        request: RequestMessage<'a>,
    ) -> sos_sdk::Result<ResponseMessage<'a>> {
        match request.method() {
            HANDSHAKE_INITIATE => {
                let mut writer = state.write().await;

                let (client_public_key, len) = 
                    request.parameters::<(Vec<u8>, usize)>()?;
                let handshake = request.body();

                let mut responder = snow::Builder::new(PATTERN.parse()?)
                    .local_private_key(writer.keypair.private_key())
                    .remote_public_key(&client_public_key)
                    .build_responder()?;

                let mut message = [0u8; 1024];
                responder.read_message(&handshake[..len], &mut message)?;
                
                let mut reply = [0u8; 1024];
                let len = responder.write_message(&[], &mut reply)?;

                let responder = responder.into_transport_mode();

                todo!("save responder protocol state");

                let reply: ResponseMessage<'_> =
                    ResponseMessage::new(request.id(),
                    StatusCode::OK,
                    Some(Ok(len)),
                    Cow::Borrowed(&reply),
                )?;
                Ok(reply)
            }
            _ => Err(sos_sdk::Error::RpcUnknownMethod(
                request.method().to_owned(),
            )),
        }
    }
}
