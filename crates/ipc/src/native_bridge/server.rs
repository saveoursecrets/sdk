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
use std::collections::HashMap;
use std::future::Future;
use std::io::ErrorKind;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio::time::sleep;
use tokio_util::codec::{FramedRead, LengthDelimitedCodec};

use super::{CHUNK_LIMIT, CHUNK_SIZE};

const HARD_LIMIT: usize = 1024 * 1024;

static CONN: Lazy<Arc<Mutex<Option<LocalSocketClient>>>> =
    Lazy::new(|| Arc::new(Mutex::new(None)));

/// Future returned by an intercept route.
pub type RouteFuture = Pin<
    Box<dyn Future<Output = Result<LocalResponse>> + Send + Sync + 'static>,
>;

/// Route handled by the native bridge.
pub type InterceptRoute = fn(LocalRequest) -> RouteFuture;

/// Probe this executable for aliveness.
fn probe(request: LocalRequest) -> RouteFuture {
    Box::pin(async move {
        let message_id = request.request_id();
        Ok(LocalResponse::with_id(StatusCode::OK, message_id))
    })
}

/// Check app status by detecting the presence of the app lock.
fn status(request: LocalRequest) -> RouteFuture {
    Box::pin(async move {
        let message_id = request.request_id();
        let paths = Paths::new_global(Paths::data_dir()?);
        let app = paths.has_app_lock()?;
        Ok(if app {
            LocalResponse::with_id(StatusCode::OK, message_id)
        } else {
            LocalResponse::with_id(StatusCode::NOT_FOUND, message_id)
        })
    })
}

/// Open a URL.
fn open_url(request: LocalRequest) -> RouteFuture {
    Box::pin(async move {
        let message_id = request.request_id();
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
            Err(_) => {
                LocalResponse::with_id(StatusCode::BAD_GATEWAY, message_id)
            }
        })
    })
}

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
        Self::with_socket_name(extension_id, IPC_GUI_SOCKET_NAME.to_string())
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
#[derive(Default)]
pub struct NativeBridgeServer {
    options: NativeBridgeOptions,
    /// Routes for internal processing.
    routes: HashMap<String, InterceptRoute>,
}

impl NativeBridgeServer {
    /// Create a server.
    pub fn new(mut options: NativeBridgeOptions) -> Self {
        let mut routes = HashMap::new();
        routes.insert("/probe".to_string(), probe as _);
        routes.insert("/status".to_string(), status as _);
        routes.insert("/open".to_string(), open_url as _);

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
        Self { options, routes }
    }

    fn find_route(&self, request: &LocalRequest) -> Option<InterceptRoute> {
        self.routes.get(request.uri.path()).copied()
    }

    /// Add an intercept route to this native proxy.
    pub fn add_intercept_route(
        &mut self,
        path: String,
        value: InterceptRoute,
    ) {
        self.routes.insert(path, value);
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

        // Read request chunks into a single request
        async fn read_chunked_request(
            stdin: &mut FramedRead<tokio::io::Stdin, LengthDelimitedCodec>,
        ) -> Result<LocalRequest> {
            let mut chunks: Vec<LocalRequest> = Vec::new();
            while let Some(Ok(buffer)) = stdin.next().await {
                let req = serde_json::from_slice::<LocalRequest>(&buffer)?;
                let chunks_len = req.chunks_len();
                chunks.push(req);
                if chunks.len() == chunks_len as usize {
                    break;
                }
            }
            Ok(LocalRequest::from_chunks(chunks))
        }

        loop {
            let channel = tx.clone();
            let sock_name = socket_name.clone();
            tokio::select! {
                result = read_chunked_request(&mut stdin) => {
                    let Ok(request) = result else {
                        let response = LocalResponse::with_id(
                            StatusCode::BAD_REQUEST,
                            0,
                        );
                        let tx = channel.clone();
                        if let Err(e) = tx.send(response.into()) {
                            tracing::warn!(
                              error = %e,
                              "native_bridge::response_channel");
                        }
                        continue;
                    };

                    let route = self.find_route(&request);
                    tokio::task::spawn(async move {
                        let tx = channel.clone();

                        tracing::trace!(
                            request = ?request,
                            "sos_native_bridge::request",
                        );

                        let message_id = request.request_id();

                        // Is this a route we intercept?
                        let is_native_route = route.is_some();
                        let response = if let Some(route) = route {
                            route(request).await
                        } else {
                            try_send_request(&sock_name, request).await
                        };

                        let result = match response {
                            Ok(response) => response,
                            Err(_) => {
                              LocalResponse::with_id(
                                if is_native_route {
                                    StatusCode::INTERNAL_SERVER_ERROR
                                } else {
                                    StatusCode::SERVICE_UNAVAILABLE
                                },
                                message_id,
                              )
                            }
                        };

                        // Send response in chunks to avoid the 1MB
                        // hard limit
                        let chunks = result.into_chunks(
                            CHUNK_LIMIT,
                            CHUNK_SIZE,
                        );
                        for chunk in chunks {
                            if let Err(e) = tx.send(chunk) {
                                tracing::warn!(
                                  error = %e,
                                  "native_bridge::response_channel");
                            }
                        }
                    });
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
                            if output.len() > HARD_LIMIT {
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
