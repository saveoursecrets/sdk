//! Proxy to an IPC server using length-prefixed JSON encoding
//! read from stdin and written to stdout.
//!
//! Used to test the browser native messaging API integration.

use crate::local_transport::{LocalRequest, LocalResponse};
use crate::Result;
use futures_util::{SinkExt, StreamExt};
use http::StatusCode;
use std::process::Stdio;
use tokio::process::{Child, Command};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

/// Client that spawns a native bridge and sends
/// and receives messages from the spawned executable.
///
/// Used to test the native bridge server.
pub struct NativeBridgeClient {
    child: Child,
    stdin: FramedWrite<tokio::process::ChildStdin, LengthDelimitedCodec>,
    stdout: FramedRead<tokio::process::ChildStdout, LengthDelimitedCodec>,
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
        })
    }

    /// Send a request to the spawned native bridge.
    pub async fn send(
        &mut self,
        request: &LocalRequest,
    ) -> Result<LocalResponse> {
        let message = serde_json::to_vec(request)?;
        self.stdin.send(message.into()).await?;

        let mut res: LocalResponse = StatusCode::IM_A_TEAPOT.into();

        while let Some(response) = self.stdout.next().await {
            let response = response?;
            let response: LocalResponse = serde_json::from_slice(&response)?;
            res = response;
            break;
        }

        Ok(res)
    }

    /// Kill the child process.
    pub async fn kill(&mut self) -> Result<()> {
        Ok(self.child.kill().await?)
    }
}
