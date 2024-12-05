use crate::{codec, decode_proto, encode_proto, Error, Result};
use futures_util::sink::SinkExt;
use interprocess::local_socket::{tokio::prelude::*, GenericNamespaced};
use sos_protocol::local_transport::{LocalRequest, LocalResponse};
use tokio_stream::StreamExt;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// Socket client for inter-process communication.
pub struct SocketClient {
    socket: Framed<LocalSocketStream, LengthDelimitedCodec>,
}

impl SocketClient {
    /// Create a client and connect the server.
    pub async fn connect(socket_name: &str) -> Result<Self> {
        let name = socket_name.to_ns_name::<GenericNamespaced>()?;
        let io = LocalSocketStream::connect(name).await?;
        Ok(Self {
            socket: codec::framed(io),
        })
    }

    /// Send a request.
    pub async fn send_request(
        &mut self,
        request: LocalRequest,
    ) -> Result<LocalResponse> {
        let request_id = request.request_id();
        let request: crate::WireLocalRequest = request.into();
        let buf = encode_proto(&request)?;
        self.socket.send(buf.into()).await?;
        let response = self.read_response().await?;

        // Response id will be zero if an error occurs
        // before a message_id could be parsed from the request
        if response.request_id() > 0 && request_id != response.request_id() {
            return Err(Error::MessageId(request_id, response.request_id()));
        }

        Ok(response)
    }

    /// Read response from the server.
    async fn read_response(&mut self) -> Result<LocalResponse> {
        let mut reply: Option<LocalResponse> = None;
        while let Some(message) = self.socket.next().await {
            match message {
                Ok(bytes) => {
                    let response: crate::WireLocalResponse =
                        decode_proto(&bytes)?;
                    reply = Some(response.try_into()?);
                    break;
                }
                Err(err) => {
                    return Err(err.into());
                }
            }
        }
        reply.ok_or(Error::NoResponse)
    }
}
