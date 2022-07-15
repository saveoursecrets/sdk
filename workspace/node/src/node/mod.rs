//! Types that describe networked nodes and their relationships.

use crate::{
    client::{
        net::{changes::ChangeStream, NetworkClient},
        LocalCache,
    },
    server::Server,
};

/// Bi-directional communication channel between nodes.
pub struct Channel {
    stream: ChangeStream,
    client: Box<dyn NetworkClient>,
}

/// Node in a network of clients.
pub struct Node {
    /// Other nodes this node is connected to.
    channels: Vec<Channel>,
    /// This nodes local cache of data.
    cache: Box<dyn LocalCache>,
    /// Server for responding to requests from other nodes.
    server: Server,
}
