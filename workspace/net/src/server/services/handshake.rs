use sos_sdk::constants::HANDSHAKE_INITIATE;

use super::Service;
use crate::{
    rpc::{RequestMessage, ResponseMessage},
    server::{Error, Result, ServerState},
};
use async_trait::async_trait;
use axum::http::StatusCode;
use mpc_protocol::{snow, ProtocolState, PATTERN};
use std::borrow::Cow;

/// Handshake service.
///
/// * `Handshake.initiate`: Client handshake initiation.
///
pub struct HandshakeService;

#[async_trait]
impl Service for HandshakeService {
    type State = ServerState;

    async fn handle<'a>(
        &self,
        state: Self::State,
        request: RequestMessage<'a>,
    ) -> Result<ResponseMessage<'a>> {
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

                let transport = responder.into_transport_mode()?;
                //let duration = writer.config.session.duration;

                let channel = writer
                    .transports
                    .new_channel(ProtocolState::Transport(transport));
                writer.transports.add_channel(
                    client_public_key,
                    channel,
                    /*
                    TransportChannel::new(
                        duration,
                        ProtocolState::Transport(transport),
                    ),
                    */
                );

                let reply: ResponseMessage<'_> = ResponseMessage::new(
                    request.id(),
                    StatusCode::OK,
                    Some(Ok(len)),
                    Cow::Owned(reply.to_vec()),
                )?;
                Ok(reply)
            }
            _ => Err(Error::RpcUnknownMethod(request.method().to_owned())),
        }
    }
}
