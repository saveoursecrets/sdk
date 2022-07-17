//! Key agent client.

use binary_stream::{BinaryWriter, Encode, Endian, MemoryStream};
use parity_tokio_ipc::{Connection, Endpoint};
use sos_core::{constants::AGENT_IDENTITY, FileIdentity};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{AgentRequest, AgentResponse, Error, Result};

/// Client for the key agent server.
pub struct KeyAgentClient {
    path: String,
    connection: Option<Connection>,
}

impl KeyAgentClient {
    /// Create a new client.
    pub fn new<S: AsRef<str>>(path: S) -> Self {
        Self {
            path: path.as_ref().to_owned(),
            connection: None,
        }
    }

    /// Connect to the server using the path for this client
    /// and store the connection.
    pub async fn connect(&mut self) -> Result<()> {
        let connection = Endpoint::connect(&self.path).await?;
        self.connection = Some(connection);
        tracing::debug!("agent client connected");
        Ok(())
    }

    /// Send a message to the server and get a reply.
    pub async fn send(
        &mut self,
        request: AgentRequest,
    ) -> Result<AgentResponse> {
        let connection =
            self.connection.as_mut().ok_or(Error::NotConnected)?;
        let buffer = AgentRequest::encode(request)?;

        tracing::debug!(size = %buffer.len(), "agent client write");

        connection.write_all(&buffer).await?;

        let mut ident = [0u8; 4];
        connection.read_exact(&mut ident).await?;

        tracing::debug!(ident = ?ident, "agent client identity");

        // Check we got the right identity bytes
        FileIdentity::read_slice(&ident, &AGENT_IDENTITY)?;

        // Read in the payload length
        let mut size = [0u8; 4];
        connection.read_exact(&mut size).await?;

        let size = u32::from_be_bytes(size);
        tracing::debug!(size = %size, "agent client payload");

        let mut buffer = vec![0u8; size as usize];
        connection.read_exact(&mut buffer).await?;
        let response = AgentResponse::decode(buffer)?;

        println!("{:#?}", response);

        //todo!("read server response");
        Ok(response)
    }
}
