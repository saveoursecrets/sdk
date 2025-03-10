//! HTTP client implementation.
use crate::{
    constants::{
        routes::v1::{
            SYNC_ACCOUNT, SYNC_ACCOUNT_EVENTS, SYNC_ACCOUNT_STATUS,
        },
        MIME_TYPE_JSON, MIME_TYPE_PROTOBUF, X_SOS_ACCOUNT_ID,
    },
    DiffRequest, DiffResponse, Error, NetworkError, PatchRequest,
    PatchResponse, Result, ScanRequest, ScanResponse, SyncClient,
    WireEncodeDecode,
};
use async_trait::async_trait;
use http::StatusCode;
use reqwest::{
    header::{AUTHORIZATION, CONTENT_TYPE, USER_AGENT},
    RequestBuilder,
};
use serde_json::Value;
use sos_core::{AccountId, Origin};
use sos_signer::ed25519::BoxedEd25519Signer;
use sos_sync::{CreateSet, SyncPacket, SyncStatus, UpdateSet};
use std::{fmt, sync::OnceLock, time::Duration};
use tracing::instrument;
use url::Url;

#[cfg(feature = "listen")]
use futures::Future;

use super::{bearer_prefix, encode_device_signature};

#[cfg(feature = "listen")]
use crate::{
    network_client::websocket::{
        ListenOptions, WebSocketChangeListener, WebSocketHandle,
    },
    ChangeNotification,
};

#[cfg(feature = "files")]
use {
    crate::transfer::{
        FileSet, FileSyncClient, FileTransfersSet, ProgressChannel,
    },
    sos_core::ExternalFile,
};

static REQUEST_USER_AGENT: OnceLock<String> = OnceLock::new();

/// Set user agent for requests.
pub fn set_user_agent(user_agent: String) {
    REQUEST_USER_AGENT.get_or_init(|| user_agent);
}

/// Client that can synchronize with a server over HTTP(S).
#[derive(Clone)]
pub struct HttpClient {
    account_id: AccountId,
    origin: Origin,
    device_signer: BoxedEd25519Signer,
    client: reqwest::Client,
    connection_id: String,
}

impl PartialEq for HttpClient {
    fn eq(&self, other: &Self) -> bool {
        self.origin == other.origin
            && self.connection_id == other.connection_id
    }
}

impl Eq for HttpClient {}

impl fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpClient")
            .field("url", self.origin.url())
            .field("connection_id", &self.connection_id)
            .finish()
    }
}

impl HttpClient {
    /// Create a new client.
    pub fn new(
        account_id: AccountId,
        origin: Origin,
        device_signer: BoxedEd25519Signer,
        connection_id: String,
    ) -> Result<Self> {
        #[cfg(not(target_arch = "wasm32"))]
        let client = reqwest::ClientBuilder::new()
            .read_timeout(Duration::from_millis(15000))
            .connect_timeout(Duration::from_millis(5000))
            .build()?;

        #[cfg(target_arch = "wasm32")]
        let client = reqwest::ClientBuilder::new().build()?;

        Ok(Self {
            account_id,
            origin,
            device_signer,
            client,
            connection_id,
        })
    }

    /// Device signing key.
    pub fn device_signer(&self) -> &BoxedEd25519Signer {
        &self.device_signer
    }

    /// Spawn a thread that listens for changes
    /// from the remote server using a websocket
    /// that performs automatic re-connection.
    #[cfg(feature = "listen")]
    pub fn listen<F>(
        &self,
        options: ListenOptions,
        handler: impl Fn(ChangeNotification) -> F + Send + Sync + 'static,
    ) -> WebSocketHandle
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let listener = WebSocketChangeListener::new(
            self.account_id.clone(),
            self.origin.clone(),
            self.device_signer.clone(),
            options,
        );
        listener.spawn(handler)
    }

    /// Total number of websocket connections on remote.
    pub async fn num_connections(server: &Url) -> Result<usize> {
        let client = reqwest::Client::new();
        let url = server.join("api/v1/sync/connections")?;
        let response = client.get(url).send().await?;
        let response = response.error_for_status()?;
        Ok(response.json::<usize>().await?)
    }

    /// Build a URL including the connection identifier
    /// in the query string.
    fn build_url(&self, route: &str) -> Result<Url> {
        let mut url = self.origin.url().join(route)?;
        url.query_pairs_mut()
            .append_pair("connection_id", &self.connection_id);
        Ok(url)
    }

    /// Check if we are able to handle a response status code
    /// and content type.
    async fn check_response(
        &self,
        response: reqwest::Response,
    ) -> Result<reqwest::Response> {
        use reqwest::header::{self, HeaderValue};
        let protobuf_type = HeaderValue::from_static(MIME_TYPE_PROTOBUF);
        let status = response.status();
        let content_type = response.headers().get(&header::CONTENT_TYPE);
        match (status, content_type) {
            // OK with the correct MIME type can be handled
            (http::StatusCode::OK, Some(content_type)) => {
                if content_type == &protobuf_type {
                    Ok(response)
                } else {
                    Err(NetworkError::ContentType(
                        content_type.to_str()?.to_owned(),
                        MIME_TYPE_PROTOBUF.to_string(),
                    )
                    .into())
                }
            }
            // Otherwise exit out early
            _ => self.error_json(response).await,
        }
    }

    /// Convert an error response that may be JSON
    /// into an error.
    async fn error_json(
        &self,
        response: reqwest::Response,
    ) -> Result<reqwest::Response> {
        use reqwest::header::{self, HeaderValue};

        let status = response.status();
        let json_type = HeaderValue::from_static(MIME_TYPE_JSON);
        let content_type = response.headers().get(&header::CONTENT_TYPE);
        if !status.is_success() {
            if let Some(content_type) = content_type {
                if content_type == json_type {
                    let value: Value = response.json().await?;
                    Err(NetworkError::ResponseJson(status, value).into())
                } else {
                    Err(NetworkError::ResponseCode(status).into())
                }
            } else {
                Ok(response)
            }
        } else {
            Ok(response)
        }
    }

    /// Set headers for all requests.
    async fn request_headers(
        &self,
        mut request: RequestBuilder,
        sign_bytes: &[u8],
    ) -> Result<RequestBuilder> {
        let device_signature = encode_device_signature(
            self.device_signer.sign(sign_bytes).await?,
        )
        .await?;
        let auth = bearer_prefix(&device_signature);

        request = request
            .header(X_SOS_ACCOUNT_ID, self.account_id.to_string())
            .header(AUTHORIZATION, auth);

        if let Some(user_agent) = REQUEST_USER_AGENT.get() {
            request = request.header(USER_AGENT, user_agent);
        }

        Ok(request)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl SyncClient for HttpClient {
    type Error = crate::Error;

    fn origin(&self) -> &Origin {
        &self.origin
    }

    #[cfg_attr(not(target_arch = "wasm32"), instrument(skip_all))]
    async fn account_exists(&self) -> Result<bool> {
        let url = self.build_url(SYNC_ACCOUNT)?;
        let sign_url = url.path().to_owned();

        tracing::debug!(url = %url, "http::account_exists");
        let request = self.client.head(url);
        let request =
            self.request_headers(request, sign_url.as_bytes()).await?;
        let response = request.send().await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::account_exists");
        let exists = match status {
            StatusCode::OK => true,
            StatusCode::NOT_FOUND => false,
            _ => {
                return Err(NetworkError::ResponseCode(status).into());
            }
        };
        Ok(exists)
    }

    #[cfg_attr(not(target_arch = "wasm32"), instrument(skip_all))]
    async fn create_account(&self, account: CreateSet) -> Result<()> {
        let body = account.encode().await?;
        let url = self.build_url(SYNC_ACCOUNT)?;

        tracing::debug!(url = %url, "http::create_account");

        let request = self
            .client
            .put(url)
            .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF);
        let request = self.request_headers(request, &body).await?;
        let response = request.body(body).send().await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::create_account");
        self.error_json(response).await?;
        Ok(())
    }

    #[cfg_attr(not(target_arch = "wasm32"), instrument(skip_all))]
    async fn update_account(&self, account: UpdateSet) -> Result<()> {
        let body = account.encode().await?;
        let url = self.build_url(SYNC_ACCOUNT)?;

        tracing::debug!(url = %url, "http::update_account");

        let request = self
            .client
            .post(url)
            .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF);
        let request = self.request_headers(request, &body).await?;
        let response = request.body(body).send().await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::update_account");
        self.error_json(response).await?;
        Ok(())
    }

    #[cfg_attr(not(target_arch = "wasm32"), instrument(skip_all))]
    async fn fetch_account(&self) -> Result<CreateSet> {
        let url = self.build_url(SYNC_ACCOUNT)?;
        let sign_url = url.path().to_owned();

        tracing::debug!(url = %url, "http::fetch_account");

        let request = self.client.get(url);
        let request =
            self.request_headers(request, sign_url.as_bytes()).await?;
        let response = request.send().await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::fetch_account");
        let response = self.check_response(response).await?;
        let buffer = response.bytes().await?;
        Ok(CreateSet::decode(buffer).await?)
    }

    #[cfg_attr(not(target_arch = "wasm32"), instrument(skip_all))]
    async fn delete_account(&self) -> Result<()> {
        let url = self.build_url(SYNC_ACCOUNT)?;

        let sign_url = url.path().to_owned();

        tracing::debug!(url = %url, "http::delete_account");

        let request = self.client.delete(url);
        let request =
            self.request_headers(request, sign_url.as_bytes()).await?;
        let response = request.send().await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::delete_account");
        self.error_json(response).await?;
        Ok(())
    }

    #[cfg_attr(not(target_arch = "wasm32"), instrument(skip_all))]
    async fn sync_status(&self) -> Result<SyncStatus> {
        let url = self.build_url(SYNC_ACCOUNT_STATUS)?;
        let sign_url = url.path().to_owned();

        tracing::debug!(url = %url, "http::sync_status");

        let request = self.client.get(url);
        let request =
            self.request_headers(request, sign_url.as_bytes()).await?;
        let response = request.send().await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::sync_status");
        let response = self.check_response(response).await?;
        let buffer = response.bytes().await?;
        Ok(SyncStatus::decode(buffer).await?)
    }

    #[cfg_attr(not(target_arch = "wasm32"), instrument(skip_all))]
    async fn sync(&self, packet: SyncPacket) -> Result<SyncPacket> {
        let body = packet.encode().await?;
        let url = self.build_url(SYNC_ACCOUNT)?;
        tracing::debug!(url = %url, "http::sync");

        let request = self
            .client
            .patch(url)
            .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF);
        let request = self.request_headers(request, &body).await?;
        let response = request.body(body).send().await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::sync");
        let response = self.check_response(response).await?;
        let buffer = response.bytes().await?;
        Ok(SyncPacket::decode(buffer).await?)
    }

    #[cfg_attr(not(target_arch = "wasm32"), instrument(skip_all))]
    async fn scan(&self, request: ScanRequest) -> Result<ScanResponse> {
        let body = request.encode().await?;
        let url = self.build_url(SYNC_ACCOUNT_EVENTS)?;

        tracing::debug!(url = %url, "http::scan");

        let request = self
            .client
            .get(url)
            .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF);
        let request = self.request_headers(request, &body).await?;
        let response = request.body(body).send().await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::scan");
        let response = self.check_response(response).await?;
        let buffer = response.bytes().await?;
        Ok(ScanResponse::decode(buffer).await?)
    }

    #[cfg_attr(not(target_arch = "wasm32"), instrument(skip_all))]
    async fn diff(&self, request: DiffRequest) -> Result<DiffResponse> {
        let body = request.encode().await?;
        let url = self.build_url(SYNC_ACCOUNT_EVENTS)?;

        tracing::debug!(url = %url, "http::diff");

        let request = self
            .client
            .post(url)
            .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF);
        let request = self.request_headers(request, &body).await?;
        let response = request.body(body).send().await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::diff");
        let response = self.check_response(response).await?;
        let buffer = response.bytes().await?;
        Ok(DiffResponse::decode(buffer).await?)
    }

    #[cfg_attr(not(target_arch = "wasm32"), instrument(skip_all))]
    async fn patch(&self, request: PatchRequest) -> Result<PatchResponse> {
        let body = request.encode().await?;
        let url = self.build_url(SYNC_ACCOUNT_EVENTS)?;
        tracing::debug!(url = %url, "http::patch");
        let request = self
            .client
            .patch(url)
            .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF);
        let request = self.request_headers(request, &body).await?;
        let response = request.body(body).send().await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::patch");
        let response = self.check_response(response).await?;
        let buffer = response.bytes().await?;
        Ok(PatchResponse::decode(buffer).await?)
    }
}

#[cfg(feature = "files")]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl FileSyncClient for HttpClient {
    type Error = crate::Error;

    #[cfg_attr(
        not(target_arch = "wasm32"),
        instrument(skip(self, path, progress, cancel))
    )]
    async fn upload_file(
        &self,
        file_info: &ExternalFile,
        path: &std::path::Path,
        progress: ProgressChannel,
        mut cancel: tokio::sync::watch::Receiver<
            crate::transfer::CancelReason,
        >,
    ) -> Result<http::StatusCode> {
        use futures::StreamExt;
        use reqwest::{
            header::{CONTENT_LENGTH, CONTENT_TYPE},
            Body,
        };
        use sos_vfs as vfs;
        use tokio::sync::mpsc;
        use tokio_stream::wrappers::ReceiverStream;
        use tokio_util::io::ReaderStream;

        let url_path = format!("api/v1/sync/file/{}", file_info);
        let url = self.build_url(&url_path)?;

        tracing::debug!(url = %url, "http::upload_file");

        let sign_url = url.path().to_owned();

        let metadata = vfs::metadata(path).await?;
        let file_size = metadata.len();
        let file = vfs::File::open(path).await?;

        let mut bytes_sent = 0;
        if let Err(error) = progress.send((bytes_sent, Some(file_size))).await
        {
            tracing::warn!(error = ?error);
        }

        let mut reader_stream = ReaderStream::new(file);

        let (tx, rx) = mpsc::channel(8);
        tokio::task::spawn(async move {
            loop {
                tokio::select! {
                  biased;
                  _ = cancel.changed() => {
                    let reason = cancel.borrow().clone();
                    tracing::debug!(reason = ?reason, "upload::canceled");
                    if let Err(e) = tx.send(Err(Error::TransferCanceled(reason))).await {
                        tracing::warn!(error = %e);
                    }
                  }
                  Some(chunk) = reader_stream.next() => {
                    if let Ok(bytes) = &chunk {
                        bytes_sent += bytes.len() as u64;
                        if let Err(e) = progress.send((bytes_sent, Some(file_size))).await {
                          tracing::warn!(error = %e);
                        }
                    }
                    if let Err(e) = tx.send(chunk.map_err(Error::from)).await {
                        tracing::error!(error = %e);
                        break;
                    }
                  }
                }
            }
        });

        let progress_stream = ReceiverStream::new(rx);

        // Use a client without the read timeout
        // as this may be a long running request
        let client = reqwest::ClientBuilder::new()
            .connect_timeout(Duration::from_millis(5000))
            .build()?;

        let request = client
            .put(url)
            .header(CONTENT_LENGTH, file_size)
            .header(CONTENT_TYPE, "application/octet-stream");
        let request =
            self.request_headers(request, sign_url.as_bytes()).await?;

        let response = request
            .body(Body::wrap_stream(progress_stream))
            .send()
            .await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::upload_file");
        if !status.is_success() && status != http::StatusCode::NOT_MODIFIED {
            self.error_json(response).await?;
        }
        Ok(status)
    }

    #[cfg_attr(
        not(target_arch = "wasm32"),
        instrument(skip(self, path, progress, cancel))
    )]
    async fn download_file(
        &self,
        file_info: &ExternalFile,
        path: &std::path::Path,
        progress: ProgressChannel,
        mut cancel: tokio::sync::watch::Receiver<
            crate::transfer::CancelReason,
        >,
    ) -> Result<http::StatusCode> {
        use sha2::{Digest, Sha256};
        use sos_vfs as vfs;
        use tokio::io::AsyncWriteExt;

        let url_path = format!("api/v1/sync/file/{}", file_info);
        let url = self.build_url(&url_path)?;

        tracing::debug!(url = %url, "http::download_file");

        let sign_url = url.path().to_owned();
        let request = self.client.get(url);
        let request =
            self.request_headers(request, sign_url.as_bytes()).await?;
        let mut response = request.send().await?;

        let file_size = response.content_length();
        let mut bytes_received = 0;
        if let Err(error) = progress.send((bytes_received, file_size)).await {
            tracing::warn!(error = ?error);
        }

        let mut download_path = path.to_path_buf();
        download_path.set_extension("download");

        let mut hasher = Sha256::new();
        let mut file = vfs::File::create(&download_path).await?;

        loop {
            tokio::select! {
                biased;
                _ = cancel.changed() => {
                  let reason = cancel.borrow().clone();
                  vfs::remove_file(download_path).await?;
                  tracing::debug!(reason = ?reason, "download::canceled");
                  return Err(Error::TransferCanceled(reason));
                }
                chunk = response.chunk() => {
                  if let Some(chunk) = chunk? {
                    file.write_all(&chunk).await?;
                    hasher.update(&chunk);

                    bytes_received += chunk.len() as u64;
                    if let Err(error) = progress.send((bytes_received, file_size)).await {
                        tracing::warn!(error = ?error);
                    }
                  } else {
                    break;
                  }
                }
            }
        }

        file.flush().await?;

        let digest = hasher.finalize();

        let digest_valid =
            digest.as_slice() == file_info.file_name().as_ref();
        if !digest_valid {
            vfs::remove_file(download_path).await?;
            return Err(Error::FileChecksumMismatch(
                file_info.file_name().to_string(),
                hex::encode(digest.as_slice()),
            ));
        }

        let status = response.status();
        tracing::debug!(status = %status, "http::download_file");

        if status == http::StatusCode::OK
            && vfs::try_exists(&download_path).await?
        {
            vfs::rename(download_path, path).await?;
        }

        self.error_json(response).await?;
        Ok(status)
    }

    #[cfg_attr(not(target_arch = "wasm32"), instrument(skip(self)))]
    async fn delete_file(
        &self,
        file_info: &ExternalFile,
    ) -> Result<http::StatusCode> {
        let url_path = format!("api/v1/sync/file/{}", file_info);
        let url = self.build_url(&url_path)?;
        let sign_url = url.path().to_owned();

        tracing::debug!(url = %url, "http::delete_file");

        let request = self.client.delete(url);
        let request =
            self.request_headers(request, sign_url.as_bytes()).await?;
        let response = request.send().await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::delete_file");
        if !status.is_success() && status != http::StatusCode::NOT_FOUND {
            self.error_json(response).await?;
        }
        Ok(status)
    }

    #[cfg_attr(not(target_arch = "wasm32"), instrument(skip(self)))]
    async fn move_file(
        &self,
        from: &ExternalFile,
        to: &ExternalFile,
    ) -> Result<http::StatusCode> {
        let url_path = format!("api/v1/sync/file/{}", from);
        let mut url = self.build_url(&url_path)?;

        url.query_pairs_mut()
            .append_pair("vault_id", &to.vault_id().to_string())
            .append_pair("secret_id", &to.secret_id().to_string())
            .append_pair("name", &to.file_name().to_string());

        tracing::debug!(from = %from, to = %to, url = %url, "http::move_file");

        let sign_url = url.path().to_owned();
        let request = self.client.post(url);
        let request =
            self.request_headers(request, sign_url.as_bytes()).await?;
        let response = request.send().await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::move_file");
        self.error_json(response).await?;
        Ok(status)
    }

    #[cfg_attr(not(target_arch = "wasm32"), instrument(skip_all))]
    async fn compare_files(
        &self,
        local_files: FileSet,
    ) -> Result<FileTransfersSet> {
        let url_path = format!("api/v1/sync/files");
        let url = self.build_url(&url_path)?;
        let sign_url = url.path().to_owned();
        let body = local_files.encode().await?;

        tracing::debug!(url = %url, "http::compare_files");

        let request = self
            .client
            .post(url)
            .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF);
        let request =
            self.request_headers(request, sign_url.as_bytes()).await?;
        let response = request.body(body).send().await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::compare_files");
        let response = self.check_response(response).await?;
        let buffer = response.bytes().await?;
        Ok(FileTransfersSet::decode(buffer).await?)
    }
}
