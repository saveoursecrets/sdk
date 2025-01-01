//! Server for the native messaging API extension helper.

use crate::{
    local_transport::{HttpMessage, LocalRequest, LocalResponse},
    memory_server::{LocalMemoryClient, LocalMemoryServer},
    web_service::WebAccounts,
    Result, ServiceAppInfo,
};
use futures_util::{SinkExt, StreamExt};
use http::{
    header::{CONTENT_LENGTH, CONTENT_TYPE},
    StatusCode,
};
use sos_account::{Account, AccountSwitcher};
use sos_logs::Logger;
use sos_protocol::{constants::MIME_TYPE_JSON, ErrorReply};
use sos_sdk::prelude::ErrorExt;
use sos_sync::SyncStorage;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio_util::codec::{FramedRead, LengthDelimitedCodec};

use super::{CHUNK_LIMIT, CHUNK_SIZE};

const HARD_LIMIT: usize = 1024 * 1024;

/// Options for a native bridge.
#[derive(Debug, Default)]
pub struct ExtensionHelperOptions {
    /// Identifier of the extension.
    pub extension_id: String,
    /// Service information.
    pub service_info: ServiceAppInfo,
}

impl ExtensionHelperOptions {
    /// Create new options.
    pub fn new(extension_id: String, service_info: ServiceAppInfo) -> Self {
        Self {
            extension_id,
            service_info,
        }
    }
}

/// Server for a native bridge proxy.
pub struct ExtensionHelperServer<A, R, E>
where
    A: Account<Error = E, NetworkResult = R> + SyncStorage,
    R: 'static,
    E: std::fmt::Debug
        + std::error::Error
        + ErrorExt
        + From<sos_sdk::Error>
        + From<sos_database::Error>
        + From<sos_account::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    #[allow(dead_code)]
    options: ExtensionHelperOptions,
    /// Client for the server.
    client: LocalMemoryClient,
    /// User accounts.
    accounts: WebAccounts<A, R, E>,
}

impl<A, R, E> ExtensionHelperServer<A, R, E>
where
    A: Account<Error = E, NetworkResult = R>
        + SyncStorage
        + Sync
        + Send
        + 'static,
    R: 'static,
    E: std::fmt::Debug
        + std::error::Error
        + ErrorExt
        + From<sos_sdk::Error>
        + From<sos_database::Error>
        + From<sos_account::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    /// Create a server.
    pub async fn new(
        options: ExtensionHelperOptions,
        accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
    ) -> Result<Self> {
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

        tracing::info!(options = ?options, "extension_helper");

        let accounts = WebAccounts::new(accounts);
        let client = LocalMemoryServer::listen(
            accounts.clone(),
            options.service_info.clone(),
        )
        .await?;

        Ok(Self {
            options,
            client,
            accounts,
        })
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

        // Send account file system change notifications
        // over stdout using the RESET_CONTENT status code
        let mut notifications = self.accounts.subscribe();
        let notifications_tx = tx.clone();
        tokio::task::spawn(async move {
            while let Ok(event) = notifications.recv().await {
                let body = serde_json::to_vec(&event)
                    .expect("to convert event to JSON");
                let mut response = LocalResponse::default();
                response.status = StatusCode::RESET_CONTENT.into();
                response.set_json_content_type();
                response.body = body;
                if let Err(e) = notifications_tx.send(response) {
                    tracing::error!(error = %e);
                }
            }
        });

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
                          let client = self.client.clone();
                          if let Err(e) = handle_request(
                            client, channel.clone(), request).await {
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
                        "sos_extension_helper::response",
                    );

                    match serde_json::to_vec(&response) {
                        Ok(output) => {
                            tracing::debug!(
                                len = %output.len(),
                                "extension_helper::stdout",
                            );
                            if output.len() > HARD_LIMIT {
                                tracing::error!(
                                    "extension_helper::exceeds_limit");
                            }
                            if let Err(e) = stdout.send(output.into()).await {
                                tracing::error!(
                                    error = %e,
                                    "extension_helper::stdout_write",
                                );
                                std::process::exit(1);
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e, "extension_helper::serde_json");
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
            "extension_helper::response_channel");
        }
    }
}

async fn handle_request(
    client: LocalMemoryClient,
    tx: mpsc::UnboundedSender<LocalResponse>,
    request: LocalRequest,
) -> Result<()> {
    let task = tokio::task::spawn(async move {
        tracing::trace!(
            request = ?request,
            "sos_extension_helper::request",
        );

        let request_id = request.request_id();
        let response = client.send(request).await;

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
              "extension_helper::chunks");
            for (index, chunk) in chunks.iter().enumerate() {
                tracing::debug!(
              index = %index,
              len = %chunk.body.len(),
              "extension_helper::chunk");
            }
        }
        for chunk in chunks {
            if let Err(e) = tx.send(chunk) {
                tracing::warn!(
                error = %e,
                "extension_helper::response_channel");
            }
        }

        Ok(())
    });
    task.await.unwrap()
}
