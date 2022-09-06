use sos_core::{
    constants::{SESSION_OFFER, SESSION_VERIFY},
    rpc::{RequestMessage, ResponseMessage, Service},
};
use web3_address::ethereum::Address;

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use web3_signature::Signature;

use crate::server::State;

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
