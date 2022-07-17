//! Key agent server.
use std::{collections::HashMap, sync::Arc};

use futures::prelude::*;
use parity_tokio_ipc::{Endpoint, SecurityAttributes};
use sos_core::{constants::AGENT_IDENTITY, FileIdentity};
use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt},
    sync::RwLock,
};

use super::{AgentRequest, AgentResponse, Key, Result, Value};

/// Server for the key agent.
pub struct KeyAgentServer {
    endpoint: Endpoint,
}

impl KeyAgentServer {
    /// Create a new key agent server with the given socket path.
    pub fn new(socket_path: String) -> Result<Self> {
        let mut endpoint = Endpoint::new(socket_path);
        endpoint.set_security_attributes(
            SecurityAttributes::empty().set_mode(0o777)?,
        );
        Ok(KeyAgentServer { endpoint })
    }

    /// Start the server running.
    pub async fn run(self) -> Result<()> {
        let incoming = self.endpoint.incoming()?;
        futures::pin_mut!(incoming);

        let keys: Arc<RwLock<HashMap<Key, Value>>> =
            Arc::new(RwLock::new(HashMap::new()));

        while let Some(result) = incoming.next().await {
            match result {
                Ok(stream) => {
                    let (mut reader, mut writer) = split(stream);

                    tracing::debug!("agent server connection");

                    let mut ident = [0u8; 4];
                    reader.read_exact(&mut ident).await?;

                    tracing::debug!(ident = ?ident, "agent server identity");

                    // Check we got the right identity bytes
                    FileIdentity::read_slice(&ident, &AGENT_IDENTITY)?;

                    // Read in the payload length
                    let mut size = [0u8; 4];
                    reader.read_exact(&mut size).await?;

                    let size = u32::from_be_bytes(size);
                    tracing::debug!(size = %size, "agent server payload");

                    let mut buffer = vec![0u8; size as usize];
                    reader.read_exact(&mut buffer).await?;

                    let request = AgentRequest::decode(buffer)?;

                    let response = match request {
                        AgentRequest::Get(key) => {
                            let reader = keys.read().await;
                            let value = reader.get(&key);
                            AgentResponse::Get(value.cloned())
                        }
                        AgentRequest::Set(key, value) => {
                            let mut writer = keys.write().await;
                            writer.insert(key, value);
                            AgentResponse::Set
                        }
                    };

                    let buffer = AgentResponse::encode(response)?;
                    tracing::debug!(size = %buffer.len(),
                        "agent server write");
                    writer.write_all(&buffer).await?;
                }
                Err(e) => {
                    tracing::error!("{}", e);
                }
            }
        }
        Ok(())
    }
}
