//! Peer network behaviours.

use libp2p::{
    identify,
    kad::{record::store::MemoryStore, Kademlia, KademliaEvent},
    rendezvous, request_response,
    swarm::{keep_alive, NetworkBehaviour},
};

use sos_core::rpc::{RequestMessage, ResponseMessage};

use super::protocol::RpcExchangeCodec;

// NOTE: do not include super::Result here as the NetworkBehaviour
// NOTE: macro expects std::result::Result.

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "ComposedEvent")]
pub(crate) struct ComposedBehaviour {
    pub(crate) request_response:
        request_response::Behaviour<RpcExchangeCodec>,
    pub(crate) kademlia: Kademlia<MemoryStore>,
    pub(crate) rendezvous: rendezvous::client::Behaviour,
    //::new(key_pair.clone()),
}

#[derive(Debug)]
pub(crate) enum ComposedEvent {
    RequestResponse(
        request_response::Event<
            RequestMessage<'static>,
            ResponseMessage<'static>,
        >,
    ),
    Kademlia(KademliaEvent),
    Rendezvous(rendezvous::client::Event),
}

impl
    From<
        request_response::Event<
            RequestMessage<'static>,
            ResponseMessage<'static>,
        >,
    > for ComposedEvent
{
    fn from(
        event: request_response::Event<
            RequestMessage<'static>,
            ResponseMessage<'static>,
        >,
    ) -> Self {
        ComposedEvent::RequestResponse(event)
    }
}

impl From<KademliaEvent> for ComposedEvent {
    fn from(event: KademliaEvent) -> Self {
        ComposedEvent::Kademlia(event)
    }
}

impl From<rendezvous::client::Event> for ComposedEvent {
    fn from(event: rendezvous::client::Event) -> Self {
        ComposedEvent::Rendezvous(event)
    }
}

#[derive(NetworkBehaviour)]
pub(crate) struct RendezvousBehaviour {
    pub(crate) identify: identify::Behaviour,
    pub(crate) rendezvous: rendezvous::server::Behaviour,
    pub(crate) keep_alive: keep_alive::Behaviour,
}
