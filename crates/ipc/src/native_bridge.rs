use futures_util::{SinkExt, StreamExt};
use sos_ipc::{IpcRequest, Result};
use sos_net::sdk::logs::Logger;
use tokio_util::codec::LengthDelimitedCodec;

/// Executable used to bridge JSON requests from browser extensions
/// using the native messaging API to the IPC channel.
#[doc(hidden)]
#[tokio::main]
pub async fn main() -> Result<()> {
    let args = std::env::args();

    // Always send log messages to disc as the browser
    // extension reads from stdout
    let logger = Logger::new(None);
    logger.init_file_subscriber(Some("info".to_string()))?;

    tracing::info!(args = ?args, "native_bridge");

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
