//! Proxy to an IPC server using length-prefixed JSON encoding
//! read from stdin and written to stdout.
//!
//! Used to support the native messaging API provided
//! by browser extensions.

use crate::{IpcRequest, Result};
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

    while let Some(Ok(buffer)) = stdin.next().await {
        let request: IpcRequest = match serde_json::from_slice(&buffer) {
            Ok(value) => value,
            Err(e) => {
                tracing::error!("Error parsing JSON: {}", e);
                continue;
            }
        };

        tracing::info!(
            request = ?request,
            "sos_native_bridge::decoded_json",
        );

        let output = serde_json::to_vec(&request).unwrap();

        tracing::info!(
            len = ?output.len(),
            "sos_native_bridge::encoded_json",
        );

        stdout.send(output.into()).await?;
    }

    Ok(())
}
