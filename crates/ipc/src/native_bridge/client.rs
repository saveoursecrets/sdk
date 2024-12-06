//! Proxy to an IPC server using length-prefixed JSON encoding
//! read from stdin and written to stdout.
//!
//! Used to test the browser native messaging API integration.

use crate::local_transport::{HttpMessage, LocalRequest, LocalResponse};
use crate::Result;
use futures_util::{SinkExt, StreamExt};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::process::{Child, Command};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

use super::{CHUNK_LIMIT, CHUNK_SIZE};

/// Client that spawns a native bridge and sends
/// and receives messages from the spawned executable.
///
/// Used to test the native bridge server.
pub struct NativeBridgeClient {
    child: Child,
    stdin: FramedWrite<tokio::process::ChildStdin, LengthDelimitedCodec>,
    stdout: FramedRead<tokio::process::ChildStdout, LengthDelimitedCodec>,
    id: AtomicU64,
}

impl NativeBridgeClient {
    /// Create a native bridge client.
    pub async fn new<C, I, S>(command: C, arguments: I) -> Result<Self>
    where
        C: AsRef<std::ffi::OsStr>,
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let mut child = Command::new(command)
            .args(arguments)
            .stdout(Stdio::piped())
            .stdin(Stdio::piped())
            .spawn()?;

        let stdout = child.stdout.take().unwrap();
        let stdin = child.stdin.take().unwrap();

        let stdin = LengthDelimitedCodec::builder()
            .native_endian()
            .new_write(stdin);

        let stdout = LengthDelimitedCodec::builder()
            .native_endian()
            .new_read(stdout);

        Ok(Self {
            child,
            stdin,
            stdout,
            id: AtomicU64::new(1),
        })
    }

    /// Send a request to the spawned native bridge.
    pub async fn send(
        &mut self,
        mut request: LocalRequest,
    ) -> Result<LocalResponse> {
        let message_id = self.id.fetch_add(1, Ordering::SeqCst);
        request.set_request_id(message_id);
        let chunks = request.into_chunks(CHUNK_LIMIT, CHUNK_SIZE);
        for request in chunks {
            let message = serde_json::to_vec(&request)?;
            self.stdin.send(message.into()).await?;
        }

        let mut chunks: Vec<LocalResponse> = Vec::new();
        while let Some(response) = self.stdout.next().await {
            let response = response?;
            let response: LocalResponse = serde_json::from_slice(&response)?;
            let chunks_len = response.chunks_len();
            chunks.push(response);
            if chunks.len() == chunks_len as usize {
                break;
            }
        }

        Ok(LocalResponse::from_chunks(chunks))
    }

    /// Kill the child process.
    pub async fn kill(&mut self) -> Result<()> {
        Ok(self.child.kill().await?)
    }
}
