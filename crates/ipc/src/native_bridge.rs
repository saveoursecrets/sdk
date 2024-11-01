use serde_json::Value;
use sos_ipc::Result;
use sos_net::sdk::logs::Logger;
use tokio::io::{
    AsyncReadExt, AsyncWriteExt, BufReader, BufWriter, Stdin, Stdout,
};

/// Executable used to bridge JSON requests from browser extensions
/// using the native messaging API to the IPC channel.
#[doc(hidden)]
#[tokio::main]
pub async fn main() -> Result<()> {
    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = BufWriter::new(tokio::io::stdout());

    let args = std::env::args();

    // Always send log messages to disc as the browser
    // extension reads from stdout
    let logger = Logger::new(None);
    logger.init_file_subscriber(Some("info".to_string()))?;

    tracing::info!(args = ?args, "native_bridge");

    loop {
        // Read the length of the message (u32)
        let length = match read_length(&mut stdin).await {
            Ok(len) => len,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                tracing::error!("Error reading message length: {}", e);
                continue;
            }
        };

        tracing::info!(len = %length, "native_bridge::read_length");

        let mut buffer = vec![0u8; length as usize];
        if let Err(e) = stdin.read_exact(&mut buffer).await {
            tracing::error!("Error reading message: {}", e);
            continue;
        }

        let json: Value = match serde_json::from_slice(&buffer) {
            Ok(value) => value,
            Err(e) => {
                tracing::error!("Error parsing JSON: {}", e);
                continue;
            }
        };

        tracing::info!(
            value = ?json,
            "sos_native_bridge::decoded_json",
        );

        let output = serde_json::to_vec(&json).unwrap();

        tracing::info!(
            len = ?output.len(),
            "sos_native_bridge::encoded_json",
        );

        write_length(&mut stdout, output.len() as u32).await?;
        stdout.write_all(&output).await?;
        stdout.flush().await?;
    }

    Ok(())
}

#[doc(hidden)]
async fn read_length(
    stdin: &mut BufReader<Stdin>,
) -> std::result::Result<u32, std::io::Error> {
    if cfg!(target_endian = "little") {
        stdin.read_u32_le().await
    } else {
        stdin.read_u32().await
    }
}

#[doc(hidden)]
async fn write_length(
    stdout: &mut BufWriter<Stdout>,
    length: u32,
) -> std::result::Result<(), std::io::Error> {
    if cfg!(target_endian = "little") {
        stdout.write_u32_le(length).await
    } else {
        stdout.write_u32(length).await
    }
}
