//! Events dispatched by the network.

use libp2p::{
    core::Multiaddr,
    request_response::{RequestId, ResponseChannel},
    PeerId,
};

use sos_core::rpc::{RequestMessage, ResponseMessage};

use super::protocol::PeerRpcResponse;

/// Network event is dispatch by the network to the
/// events stream.
#[derive(Debug)]
pub enum NetworkEvent {
    /// Dispatched when changes to the network have been made.
    Change(ChangeEvent),
    /// Dispatched for RPC requests and responses.
    Message(MessageEvent),
}

/// Change event dispatched when changes to the network have been made.
#[derive(Debug)]
pub enum ChangeEvent {
    /// Event dispatched when a new listen address becomes available.
    NewListenAddr {
        /// Local peer id.
        peer_id: PeerId,
        /// Listening address.
        address: Multiaddr,
    },
    /// Event dispatched when a connection is established.
    ConnectionEstablished {
        /// Remote peer id.
        peer_id: PeerId,
    },
    /// Event dispatched when a connection is closed.
    ConnectionClosed {
        /// Remote peer id.
        peer_id: PeerId,
    },
}

/// Message event dispatched when an RPC message is sent or received.
#[derive(Debug)]
pub enum MessageEvent {
    /// Message event for an inbound request.
    InboundRequest {
        /// Remote peer.
        peer: PeerId,
        /// Request message.
        request: RequestMessage<'static>,
        /// Channel to route the response to.
        channel: ResponseChannel<PeerRpcResponse>,
    },
    /// Message event for an outbound response.
    OutboundResponse {
        /// Remote peer.
        peer: PeerId,
        /// The request identifier.
        request_id: RequestId,
        /// The response message.
        response: ResponseMessage<'static>,
    },
}
