//! Types that describe networked nodes and their relationships.

use crate::{
    client::{
        net::{changes::ChangeStream, NetworkClient},
        LocalCache,
    },
    server::Server,
};

mod error;

pub use error::Error;

/// Result type for the node module.
pub type Result<T> = std::result::Result<T, error::Error>;

/// Bi-directional communication channel between nodes.
pub struct Channel {
    stream: ChangeStream,
    client: Box<dyn NetworkClient>,
}

/// Node in a network of clients.
pub struct Node {
    /// Other nodes this node is connected to.
    channels: Vec<Channel>,

    /*
    /// This nodes local cache of data.
    cache: Box<dyn LocalCache>,
    */
    /// Server for responding to requests from other nodes.
    server: Server,
}

impl Node {
    /// Create a new node.
    pub fn new() -> Self {
        Self {
            channels: Default::default(),
            server: Server::new(),
        }
    }

    /// Start listening for new connections.
    pub fn listen(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;

    #[test]
    fn node_connect() -> Result<()> {
        Ok(())
    }
}
