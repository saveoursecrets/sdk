//! Proxy to an IPC server using length-prefixed JSON encoding
//! read from stdin and written to stdout.
//!
//! Used to support the native messaging API provided
//! by browser extensions.

use crate::Result;
use futures_util::{SinkExt, StreamExt};
use sos_protocol::local_transport::{LocalRequest, LocalResponse};
use tokio_util::codec::LengthDelimitedCodec;

/// Send a request to a native bridge executable.
pub async fn send<C, I, S>(
    command: C,
    arguments: I,
    request: &LocalRequest,
) -> Result<LocalResponse>
where
    C: AsRef<std::ffi::OsStr>,
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    use std::process::Stdio;
    use tokio::process::Command;

    let mut child = Command::new(command)
        .args(arguments)
        .stdout(Stdio::piped())
        .stdin(Stdio::piped())
        .spawn()?;

    let stdout = child.stdout.take().unwrap();
    let stdin = child.stdin.take().unwrap();

    let mut stdin = LengthDelimitedCodec::builder()
        .native_endian()
        .new_write(stdin);

    let mut stdout = LengthDelimitedCodec::builder()
        .native_endian()
        .new_read(stdout);

    let message = serde_json::to_vec(request)?;
    stdin.send(message.into()).await?;

    while let Some(response) = stdout.next().await {
        let response = response?;
        let response: LocalResponse = serde_json::from_slice(&response)?;
        return Ok(response);
    }

    unreachable!();
}
