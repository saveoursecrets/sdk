//! Server for the native messaging API bridge.

use crate::{
    local_transport::{HttpMessage, LocalRequest, LocalResponse},
    memory::{LocalMemoryClient, LocalMemoryServer},
    Result,
};
use futures_util::{SinkExt, StreamExt};
use http::{
    header::{CONTENT_LENGTH, CONTENT_TYPE},
    StatusCode,
};
use sos_protocol::{
    constants::MIME_TYPE_JSON, ErrorReply, Merge, SyncStorage,
};
use sos_sdk::{
    logs::Logger,
    prelude::{Account, AccountSwitcher, ErrorExt},
};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio_util::codec::{FramedRead, LengthDelimitedCodec};

use super::{CHUNK_LIMIT, CHUNK_SIZE};

const HARD_LIMIT: usize = 1024 * 1024;

/// Options for a native bridge.
#[derive(Debug, Default)]
pub struct NativeBridgeOptions {
    /// Identifier of the extension.
    pub extension_id: String,
}

impl NativeBridgeOptions {
    /// Create new options.
    pub fn new(extension_id: String) -> Self {
        Self { extension_id }
    }
}

/// Server for a native bridge proxy.
pub struct NativeBridgeServer {
    #[allow(dead_code)]
    options: NativeBridgeOptions,
    /// Client for the server.
    client: LocalMemoryClient,
}

impl NativeBridgeServer {
    /// Create a server.
    pub async fn new<A, R, E>(
        options: NativeBridgeOptions,
        accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
    ) -> Result<Self>
    where
        A: Account<Error = E, NetworkResult = R>
            + SyncStorage
            + Merge
            + Sync
            + Send
            + 'static,
        R: 'static,
        E: std::fmt::Debug
            + ErrorExt
            + From<sos_sdk::Error>
            + From<std::io::Error>
            + 'static,
    {
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

        tracing::info!(options = ?options, "native_bridge");

        let client =
            LocalMemoryServer::listen(accounts, Default::default()).await?;

        Ok(Self { options, client })
    }

    /// Start a native bridge server listening.
    pub async fn listen(&self) {
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
            let mut channel = tx.clone();
            tokio::select! {
                result = read_chunked_request(&mut stdin) => {
                    match result {
                        Ok(request) => {
                          if let Err(e) = self.handle_request(
                            request, &mut channel).await {
                            self.internal_error(
                              StatusCode::INTERNAL_SERVER_ERROR,
                              e,
                              &mut channel);
                          }
                        }
                        Err(e) => {
                          self.internal_error(
                            StatusCode::BAD_REQUEST,
                            e,
                            &mut channel);
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
                            if output.len() > HARD_LIMIT {
                                tracing::error!(
                                    "native_bridge::exceeds_limit");
                            }
                            if let Err(e) = stdout.send(output.into()).await {
                                tracing::error!(
                                    error = %e,
                                    "native_bridge::stdout_write",
                                );
                                std::process::exit(1);
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e, "native_bridge::serde_json");
                            std::process::exit(1);
                        }
                    }

                }
            }
        }
    }

    fn internal_error(
        &self,
        status: StatusCode,
        err: impl std::fmt::Display,
        tx: &mut mpsc::UnboundedSender<LocalResponse>,
    ) {
        let mut response = LocalResponse::with_id(status, 0);
        let error = ErrorReply::new_message(status, err);
        let bytes = serde_json::to_vec(&error).unwrap();
        response.headers_mut().insert(
            CONTENT_TYPE.to_string(),
            vec![MIME_TYPE_JSON.to_string()],
        );
        response.headers_mut().insert(
            CONTENT_LENGTH.to_string(),
            vec![bytes.len().to_string()],
        );
        response.body = bytes;

        // let tx = channel.clone();
        if let Err(e) = tx.send(response.into()) {
            tracing::warn!(
            error = %e,
            "native_bridge::response_channel");
        }
    }

    async fn handle_request(
        &self,
        request: LocalRequest,
        tx: &mut mpsc::UnboundedSender<LocalResponse>,
    ) -> Result<()> {
        let client = self.client.clone();

        tracing::trace!(
            request = ?request,
            "sos_native_bridge::request",
        );

        let request_id = request.request_id();

        let response = client.send_request(request).await;

        let mut result = match response {
            Ok(response) => response,
            Err(e) => {
                tracing::error!(error = %e);
                StatusCode::INTERNAL_SERVER_ERROR.into()
            }
        };

        result.set_request_id(request_id);

        // Send response in chunks to avoid the 1MB
        // hard limit
        let chunks = result.into_chunks(CHUNK_LIMIT, CHUNK_SIZE);

        if chunks.len() > 1 {
            tracing::debug!(
                len = %chunks.len(),
                "native_bridge::chunks");
            for (index, chunk) in chunks.iter().enumerate() {
                tracing::debug!(
                index = %index,
                len = %chunk.body.len(),
                "native_bridge::chunk");
            }
        }
        for chunk in chunks {
            if let Err(e) = tx.send(chunk) {
                tracing::warn!(
                  error = %e,
                  "native_bridge::response_channel");
            }
        }

        Ok(())
    }
}
