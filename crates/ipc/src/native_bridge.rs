//! Proxy to an IPC server using length-prefixed JSON encoding
//! read from stdin and written to stdout.
//!
//! Used to support the native messaging API provided
//! by browser extensions.

use crate::{
    Error, IpcRequest, IpcRequestBody, IpcResponse, IpcResponseBody, Result,
    SocketClient,
};
use futures_util::{SinkExt, StreamExt};
use sos_net::sdk::{logs::Logger, prelude::IPC_GUI_SOCKET_NAME, Paths};
use std::{io::ErrorKind, time::Duration};
use tokio::time::sleep;
use tokio_util::codec::LengthDelimitedCodec;

/// Extension id used by the CLI.
pub const CLI_EXTENSION_ID: &str = "com.saveoursecrets.sos";

/// Extension id used by Chrome.
pub const CHROME_EXTENSION_ID: &str =
    "chrome-extension://fdgmkdbcpncojjipdjkaadcomcjcbhbi/";

/// Extension id used by Firefox.
pub const FIREFOX_EXTENSION_ID: &str =
    "{86d5958d-dd72-47bc-8a7e-b62c3363752b}";

const ALLOWED_EXTENSIONS: [&str; 3] =
    [CLI_EXTENSION_ID, CHROME_EXTENSION_ID, FIREFOX_EXTENSION_ID];

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
    if !ALLOWED_EXTENSIONS.contains(&&options.extension_id[..]) {
        return Err(Error::NativeBridgeDenied(options.extension_id));
    }

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

    let mut client = try_connect(&socket_name).await;

    while let Some(Ok(buffer)) = stdin.next().await {
        let response = match serde_json::from_slice::<IpcRequest>(&buffer) {
            Ok(request) => {
                tracing::debug!(
                    request = ?request,
                    "sos_native_bridge::request",
                );
                let message_id = request.message_id;
                match handle_request(&mut client, request, &socket_name).await
                {
                    Ok(response) => response,
                    Err(e) => IpcResponse::Error {
                        message_id,
                        payload: Error::NativeBridgeClientProxy(
                            e.to_string(),
                        )
                        .into(),
                    },
                }
            }
            Err(e) => IpcResponse::Error {
                message_id: 0,
                payload: Error::NativeBridgeJsonParse(e.to_string()).into(),
            },
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

/// Handle an incoming request intercepting some
/// requests which can be handled without sending
/// over the IPC channel.
async fn handle_request(
    client: &mut SocketClient,
    request: IpcRequest,
    socket_name: &str,
) -> Result<IpcResponse> {
    let message_id = request.message_id;
    match &request.payload {
        IpcRequestBody::Status => {
            let paths = Paths::new_global(Paths::data_dir()?);
            let app = paths.has_app_lock()?;
            let request = IpcRequest {
                message_id,
                payload: IpcRequestBody::Ping,
            };
            let ipc =
                match try_send_request(client, request, socket_name).await {
                    Ok(_) => true,
                    _ => false,
                };
            Ok(IpcResponse::Value {
                message_id,
                payload: IpcResponseBody::Status { app, ipc },
            })
        }
        IpcRequestBody::OpenUrl(url) => {
            let result = open::that_detached(&url);
            Ok(IpcResponse::Value {
                message_id,
                payload: IpcResponseBody::OpenUrl(result.is_ok()),
            })
        }
        _ => try_send_request(client, request, socket_name).await,
    }
}

async fn try_connect(socket_name: &str) -> SocketClient {
    let retry_delay = Duration::from_secs(1);
    loop {
        match SocketClient::connect(&socket_name).await {
            Ok(client) => return client,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "native_bridge::connect",
                );
                sleep(retry_delay).await;
            }
        }
    }
}

/// Send an IPC request and retry for certain types of IO error.
async fn try_send_request(
    client: &mut SocketClient,
    request: IpcRequest,
    socket_name: &str,
) -> Result<IpcResponse> {
    let mut attempts = 0;
    let max_retries = 60;
    let retry_delay = Duration::from_millis(500);

    loop {
        match client.send_request(request.clone()).await {
            Ok(response) => return Ok(response),
            Err(e) => match e {
                Error::Io(io_err) => match io_err.kind() {
                    ErrorKind::BrokenPipe => {
                        attempts += 1;
                        tracing::warn!(
                            kind = %io_err.kind(),
                            attempts = %attempts,
                            max_retries = %max_retries,
                            "native_bridge::send_error",
                        );
                        sleep(retry_delay).await;

                        match SocketClient::connect(&socket_name).await {
                            Ok(conn) => {
                                *client = conn;
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "native_bridge::reconnect_failed",
                                );
                            }
                        }
                    }
                    _ => return Err(Error::Io(io_err)),
                },
                _ => return Err(e),
            },
        }
    }
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
