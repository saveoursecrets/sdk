use sos_sdk::{
    constants::HANDSHAKE_INITIATE,
    rpc::{RequestMessage, ResponseMessage, Service},
};

use async_trait::async_trait;
use std::sync::Arc;
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
                todo!();
                /*
                let address = request.parameters::<Address>()?;
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
                */
            }
            _ => Err(sos_sdk::Error::RpcUnknownMethod(
                request.method().to_owned(),
            )),
        }
    }
}
