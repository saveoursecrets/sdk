//! Proxy to an IPC server using length-prefixed JSON encoding
//! read from stdin and written to stdout.
//!
//! Used to support the native messaging API provided
//! by browser extensions.

use crate::{Error, IpcResponse, Result, SocketClient};
use futures_util::{SinkExt, StreamExt};
use sos_net::sdk::{logs::Logger, prelude::IPC_GUI_SOCKET_NAME};
use tokio_util::codec::LengthDelimitedCodec;

/// Options for a native bridge.
#[derive(Debug, Default)]
pub struct NativeBridgeOptions {
    /// Identifier of the extension.
    pub extension_id: String,
    /// Socket name for the IPC server.
    pub socket_name: Option<String>,
}

impl NativeBridgeOptions {
    /// Create new options.
    pub fn new(extension_id: String) -> Self {
        Self {
            extension_id,
            ..Default::default()
        }
    }
}

/// Run a native bridge.
pub async fn run(options: NativeBridgeOptions) -> Result<()> {
    // Always send log messages to disc as the browser
    // extension reads from stdout
    let logger = Logger::new(None);
    logger.init_file_subscriber(Some("info".to_string()))?;

    let socket_name = options
        .socket_name
        .as_ref()
        .map(|s| &s[..])
        .unwrap_or(IPC_GUI_SOCKET_NAME);

    tracing::info!(options = ?options, "native_bridge");

    let mut stdin = LengthDelimitedCodec::builder()
        .native_endian()
        .new_read(tokio::io::stdin());

    let mut stdout = LengthDelimitedCodec::builder()
        .native_endian()
        .new_write(tokio::io::stdout());

    let mut client = SocketClient::connect(&socket_name).await?;

    while let Some(Ok(buffer)) = stdin.next().await {
        let response = match serde_json::from_slice(&buffer) {
            Ok(request) => {
                tracing::debug!(
                    request = ?request,
                    "sos_native_bridge::request",
                );
                match client.send_request(request).await {
                    Ok(response) => response,
                    Err(e) => IpcResponse::Error(
                        Error::NativeBridgeClientProxy(e.to_string()).into(),
                    ),
                }
            }
            Err(e) => IpcResponse::Error(
                Error::NativeBridgeJsonParse(e.to_string()).into(),
            ),
        };

        tracing::debug!(
            response = ?response,
            "sos_native_bridge::response",
        );

        let output = serde_json::to_vec(&response)?;
        stdout.send(output.into()).await?;
    }

    Ok(())
}

#[cfg(feature = "native-send")]
/// Send a request to a native bridge executable.
pub async fn send<C, I, S>(
    command: C,
    arguments: I,
    request: &crate::IpcRequest,
) -> Result<IpcResponse>
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
        let response: IpcResponse = serde_json::from_slice(&response)?;
        return Ok(response);
    }

    unreachable!();
}
