use std::{
    collections::{hash_map, HashMap, HashSet},
    io, iter,
};

use either::Either;
use futures::channel::{mpsc, oneshot};
use futures::prelude::*;

use libp2p::{
    core::Multiaddr,
    identity,
    kad::{
        record::store::MemoryStore, GetProvidersOk, Kademlia, KademliaEvent,
        QueryId, QueryResult,
    },
    multiaddr::Protocol,
    request_response::{self, ProtocolSupport, RequestId, ResponseChannel},
    swarm::{
        ConnectionHandlerUpgrErr, NetworkBehaviour, Swarm, SwarmBuilder,
        SwarmEvent,
    },
    PeerId,
};

use sos_core::rpc::{RequestMessage, ResponseMessage};

use super::{protocol::*, transport};

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "ComposedEvent")]
pub(crate) struct ComposedBehaviour {
    pub(crate) request_response: request_response::Behaviour<RpcExchangeCodec>,
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
