//! Types that describe networked nodes and their relationships.

use sos_core::{signer::Signer, wal::WalProvider, PatchProvider};

use crate::client::{
    net::{changes::ChangeStream, NetworkClient},
    node_cache::NodeCache,
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
pub struct Node<S, W, P>
where
    S: Signer + Send + Sync + 'static,
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    /// Other nodes this node is connected to.
    channels: Vec<Channel>,

    /// This nodes local cache of data.
    cache: NodeCache<S, W, P>,
    /*
    /// Server for responding to requests from other nodes.
    server: Server,
    */
}

impl<S, W, P> Node<S, W, P>
where
    S: Signer + Send + Sync + 'static,
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    /// Create a new node.
    pub fn new(cache: NodeCache<S, W, P>) -> Self {
        Self {
            channels: Default::default(),
            cache,
            //server: Server::new(),
        }
    }

    /*
    /// Start listening for new connections.
    pub async fn listen(&self) -> Result<()> {
        let server = Server::new();
        Ok(())
    }
    */
}

#[cfg(test)]
mod test {

    use anyhow::Result;

    #[test]
    fn node_connect() -> Result<()> {
        Ok(())
    }
}
