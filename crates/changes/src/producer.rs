//! Producer for change notifications on a named pipe.
use crate::Result;
use interprocess::local_socket::{tokio::prelude::*, GenericNamespaced};

/// Producer socket connect for inter-process communication.
pub struct ChangeProducer {
    socket_name: String,
}

impl ChangeProducer {
    /// Create a connection to the named pipe.
    pub async fn connect(socket_name: impl Into<String>) -> Result<Self> {
        Ok(Self {
            socket_name: socket_name.into(),
        })
    }

    /// Send a local request.
    pub async fn send_request(&mut self) -> Result<()> {
        let name =
            self.socket_name.clone().to_ns_name::<GenericNamespaced>()?;
        let io = LocalSocketStream::connect(name).await?;
        todo!();
    }
}
