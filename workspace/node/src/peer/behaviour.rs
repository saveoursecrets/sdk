use libp2p::{
    kad::{record::store::MemoryStore, Kademlia, KademliaEvent},
    request_response,
    swarm::NetworkBehaviour,
};

use super::protocol::{PeerRpcRequest, PeerRpcResponse, RpcExchangeCodec};

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "ComposedEvent")]
pub(crate) struct ComposedBehaviour {
    pub(crate) request_response:
        request_response::Behaviour<RpcExchangeCodec>,
    pub(crate) kademlia: Kademlia<MemoryStore>,
}

#[derive(Debug)]
pub(crate) enum ComposedEvent {
    RequestResponse(request_response::Event<PeerRpcRequest, PeerRpcResponse>),
    Kademlia(KademliaEvent),
}

impl From<request_response::Event<PeerRpcRequest, PeerRpcResponse>>
    for ComposedEvent
{
    fn from(
        event: request_response::Event<PeerRpcRequest, PeerRpcResponse>,
    ) -> Self {
        ComposedEvent::RequestResponse(event)
    }
}

impl From<KademliaEvent> for ComposedEvent {
    fn from(event: KademliaEvent) -> Self {
        ComposedEvent::Kademlia(event)
    }
}
