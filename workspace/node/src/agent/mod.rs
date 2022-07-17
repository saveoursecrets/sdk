//! Key management agent.
//!
//! Stores identity signing keys in memory so that a user
//! does not have to keep entering the keystore passphrase
//! when a key agent is active.

mod error;

#[cfg(feature = "agent-client")]
pub mod client;
#[cfg(any(feature = "agent-client", feature = "agent-server"))]
mod message;
#[cfg(feature = "agent-server")]
pub mod server;

#[cfg(any(feature = "agent-client", feature = "agent-server"))]
pub use message::{AgentRequest, AgentResponse};

pub use error::Error;

/// Result type for the agent module.
pub type Result<T> = std::result::Result<T, error::Error>;

#[cfg(all(feature = "agent-client", feature = "agent-server"))]
#[cfg(test)]
mod test {
    use super::{
        client::KeyAgentClient, server::KeyAgentServer, AgentRequest,
        AgentResponse,
    };
    use anyhow::Result;
    use futures::{
        future::{ready, select, Either},
        FutureExt,
    };
    use parity_tokio_ipc::{dummy_endpoint, Endpoint};
    use std::{path::Path, time::Duration};
    use tokio::{io::AsyncWriteExt, sync::oneshot};

    async fn run_server(path: String) {
        let server =
            KeyAgentServer::new(path).expect("failed to prepare server");
        server.run().await.unwrap()
    }

    #[tokio::test]
    async fn ipc_agent() -> Result<()> {
        let path = dummy_endpoint();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let server = select(Box::pin(run_server(path.clone())), shutdown_rx)
            .then(|either| {
                match either {
                    Either::Right((_, server)) => {
                        drop(server);
                    }
                    _ => unreachable!(),
                };
                ready(())
            });

        tokio::spawn(server);
        tokio::time::sleep(Duration::from_secs(2)).await;

        let mut client_0 = KeyAgentClient::new(&path);
        client_0.connect().await?;

        let msg = "hello".as_bytes().to_vec();
        let message = AgentRequest(msg);
        let response = client_0.send(message).await;

        // Delay so that messages can be processed
        tokio::time::sleep(Duration::from_secs(2)).await;

        // shutdown server
        if let Ok(()) = shutdown_tx.send(()) {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let path = Path::new(&path);
            assert!(!path.exists());
        }

        Ok(())
    }
}
