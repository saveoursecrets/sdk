//! Key management agent.
//!
//! Stores identity signing keys in memory so that a user
//! does not have to keep entering the keystore passphrase
//! when a key agent is active.

use std::path::PathBuf;

mod error;

#[cfg(feature = "agent-client")]
pub mod client;
#[cfg(any(feature = "agent-client", feature = "agent-server"))]
mod message;
#[cfg(feature = "agent-server")]
pub mod server;

#[cfg(any(feature = "agent-client", feature = "agent-server"))]
pub use message::{AgentRequest, AgentResponse, Key, Value};

pub use error::Error;

/// Result type for the agent module.
pub type Result<T> = std::result::Result<T, error::Error>;

/// Default socket path.
pub fn default_path() -> Option<PathBuf> {
    crate::cache_dir().map(|d| d.join("agent.sock"))
}

#[cfg(all(feature = "agent-client", feature = "agent-server"))]
#[cfg(test)]
mod test {
    use super::{
        client::KeyAgentClient, server::KeyAgentServer, AgentRequest,
        AgentResponse, Key, Value,
    };
    use anyhow::Result;
    use futures::{
        future::{ready, select, Either},
        FutureExt,
    };
    use parity_tokio_ipc::dummy_endpoint;
    use rand::Rng;
    use std::{path::Path, time::Duration};
    use tokio::sync::oneshot;

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

        let mut client_1 = KeyAgentClient::new(&path);
        client_1.connect().await?;

        let key: Key =
            hex::decode("7bac27741f270cf71fbf1fb20f598f910766ad3c")?
                .as_slice()
                .try_into()?;
        let value: Value = rand::thread_rng().gen();

        let message = AgentRequest::Set(key.clone(), value.clone());
        let response = client_0.send(message).await?;
        assert_eq!(AgentResponse::Set, response);

        let message = AgentRequest::Get(key);
        let response = client_1.send(message).await?;
        assert_eq!(AgentResponse::Get(Some(value)), response);

        // Delay so that messages can be processed
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Shutdown server
        if let Ok(()) = shutdown_tx.send(()) {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let path = Path::new(&path);
            assert!(!path.exists());
        }

        Ok(())
    }
}
