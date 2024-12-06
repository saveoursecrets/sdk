//! Server for the native messaging API bridge.

use crate::{
    client::LocalSocketClient,
    local_transport::{HttpMessage, LocalRequest, LocalResponse},
    Error, Result,
};
use futures_util::{SinkExt, StreamExt};
use http::StatusCode;
use once_cell::sync::Lazy;
use sos_sdk::{logs::Logger, prelude::IPC_GUI_SOCKET_NAME, url::Url, Paths};
use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio::time::sleep;
use tokio_util::codec::LengthDelimitedCodec;

const LIMIT: usize = 1024 * 1024;

static CONN: Lazy<Arc<Mutex<Option<LocalSocketClient>>>> =
    Lazy::new(|| Arc::new(Mutex::new(None)));

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

    /// Create new options with a socket name.
    pub fn with_socket_name(
        extension_id: String,
        socket_name: String,
    ) -> Self {
        Self {
            extension_id,
            socket_name: Some(socket_name),
        }
    }
}

/// Server for a native bridge proxy.
#[derive(Debug, Default)]
pub struct NativeBridgeServer {
    options: NativeBridgeOptions,
}

impl NativeBridgeServer {
    /// Create a server.
    pub fn new(mut options: NativeBridgeOptions) -> Self {
        let log_level = std::env::var("SOS_NATIVE_BRIDGE_LOG_LEVEL")
            .map(|s| s.to_string())
            .ok()
            .unwrap_or("debug".to_string());

        // Always send log messages to disc as the browser
        // extension reads from stdout
        let logger = Logger::new(None);
        if let Err(err) = logger.init_file_subscriber(Some(log_level)) {
            eprintln!("{}", err);
            std::process::exit(1);
        }

        let socket_name = options
            .socket_name
            .as_ref()
            .map(|s| &s[..])
            .unwrap_or(IPC_GUI_SOCKET_NAME)
            .to_string();

        options.socket_name = Some(socket_name);
        tracing::info!(options = ?options, "native_bridge");
        Self { options }
    }

    /// Start a native bridge server listening.
    pub async fn listen(&self) {
        let socket_name = self.options.socket_name.clone().unwrap();
        let mut stdin = LengthDelimitedCodec::builder()
            .native_endian()
            .new_read(tokio::io::stdin());

        let mut stdout = LengthDelimitedCodec::builder()
            .native_endian()
            .new_write(tokio::io::stdout());

        let (tx, mut rx) = mpsc::unbounded_channel::<LocalResponse>();

        loop {
            let channel = tx.clone();
            let sock_name = socket_name.clone();
            tokio::select! {
                Some(Ok(buffer)) = stdin.next() => {
                    match serde_json::from_slice::<LocalRequest>(&buffer) {
                        Ok(request) => {
                            tokio::task::spawn(async move {
                                let tx = channel.clone();

                                tracing::trace!(
                                    request = ?request,
                                    "sos_native_bridge::request",
                                );

                                let message_id = request.request_id();

                                // Is this a command we handle internally?
                                let response = if is_native_request(&request) {
                                    handle_native_request(
                                        request,
                                    )
                                    .await
                                } else {
                                    try_send_request(&sock_name, request).await
                                };

                                let result = match response {
                                    Ok(response) => response,
                                    Err(_) => {
                                      LocalResponse::with_id(
                                        StatusCode::SERVICE_UNAVAILABLE,
                                        message_id,
                                      )
                                    }
                                };

                                if let Err(e) = tx.send(result) {
                                    tracing::warn!(
                                      error = %e,
                                      "native_bridge::response_channel");
                                }
                            });
                        }
                        Err(_) => {
                            let response = LocalResponse::with_id(StatusCode::BAD_REQUEST, 0);
                            let tx = channel.clone();
                            if let Err(e) = tx.send(response.into()) {
                                tracing::warn!(
                                  error = %e,
                                  "native_bridge::response_channel");
                            }
                        }
                    }
                }
                Some(response) = rx.recv() => {
                    tracing::trace!(
                        response = ?response,
                        "sos_native_bridge::response",
                    );

                    match serde_json::to_vec(&response) {
                        Ok(output) => {
                            tracing::debug!(
                                len = %output.len(),
                                "native_bridge::stdout",
                            );
                            if output.len() > LIMIT {
                                tracing::error!("native_bridge::exceeds_limit");
                            }
                            if let Err(e) = stdout.send(output.into()).await {
                                tracing::error!(error = %e, "native_bridge::stdout_write");
                                std::process::exit(1);
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "native_bridge::serde_json");
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
    }
}

async fn connect(socket_name: &str) -> Arc<Mutex<Option<LocalSocketClient>>> {
    let mut conn = CONN.lock().await;
    if conn.is_some() {
        return Arc::clone(&*CONN);
    }
    let socket_client = try_connect(socket_name).await;
    *conn = Some(socket_client);
    return Arc::clone(&*CONN);
}

async fn try_connect(socket_name: &str) -> LocalSocketClient {
    let retry_delay = Duration::from_secs(1);
    loop {
        match LocalSocketClient::connect(socket_name).await {
            Ok(client) => return client,
            Err(e) => {
                tracing::trace!(
                    error = %e,
                    "native_bridge::connect",
                );
                sleep(retry_delay).await;
            }
        }
    }
}

/// Send an IPC request and reconnect for certain types of IO error.
async fn try_send_request(
    socket_name: &str,
    request: LocalRequest,
) -> Result<LocalResponse> {
    loop {
        let conn = connect(socket_name).await;
        let mut lock = conn.lock().await;
        let client = lock.as_mut().unwrap();
        match client.send_request(request.clone()).await {
            Ok(response) => return Ok(response),
            Err(e) => match e {
                Error::Io(io_err) => match io_err.kind() {
                    ErrorKind::BrokenPipe => {
                        // Move the broken client out
                        // so the next attempt to connect
                        // will create a new client
                        lock.take();
                    }
                    _ => return Err(Error::Io(io_err)),
                },
                _ => return Err(e),
            },
        }
    }
}

/// Native requests are those handled by this native bridge.
fn is_native_request(request: &LocalRequest) -> bool {
    match request.uri.path() {
        "/probe" => true,
        "/status" => true,
        "/open-url" => true,
        _ => false,
    }
}

async fn handle_native_request(
    request: LocalRequest,
) -> Result<LocalResponse> {
    let message_id = request.request_id();
    match request.uri.path() {
        "/probe" => Ok(LocalResponse::with_id(StatusCode::OK, message_id)),
        "/status" => {
            let paths = Paths::new_global(Paths::data_dir()?);
            let app = paths.has_app_lock()?;
            Ok(if app {
                LocalResponse::with_id(StatusCode::OK, message_id)
            } else {
                LocalResponse::with_id(StatusCode::NOT_FOUND, message_id)
            })
        }
        "/open-url" => {
            let url = Url::parse(&request.uri.to_string()).unwrap();

            let Some(target) =
                url.query_pairs().find(|(k, _)| k == "url").map(|(_, v)| v)
            else {
                return Ok(LocalResponse::with_id(
                    StatusCode::BAD_REQUEST,
                    message_id,
                ));
            };

            Ok(match open::that_detached(&*target) {
                Ok(_) => LocalResponse::with_id(StatusCode::OK, message_id),
                Err(_) => LocalResponse::with_id(
                    StatusCode::BAD_GATEWAY,
                    message_id,
                ),
            })
        }
        _ => unreachable!("update to is_native_request() required"),
    }
}
