//! HTTP client implementation.
use async_trait::async_trait;
use futures::{Future, StreamExt};
use reqwest::header::AUTHORIZATION;
use sos_sdk::{
    constants::MIME_TYPE_SOS,
    decode, encode,
    sha2::{Digest, Sha256},
    signer::{ecdsa::BoxedEcdsaSigner, ed25519::BoxedEd25519Signer},
    sync::{ChangeSet, Origin, SyncPacket, SyncStatus, UpdateSet},
};
use tracing::instrument;

use serde_json::Value;

#[cfg(feature = "listen")]
use crate::ChangeNotification;

#[cfg(feature = "listen")]
use super::websocket::WebSocketChangeListener;

#[cfg(feature = "device")]
use crate::sdk::sync::DeviceDiff;

#[cfg(feature = "files")]
use crate::sdk::storage::files::{ExternalFile, FileSet, FileTransfersSet};

#[cfg(feature = "files")]
use crate::client::ProgressChannel;

use crate::client::{Error, Result, SyncClient};
use std::{fmt, path::Path, sync::Arc, time::Duration};
use url::Url;

#[cfg(feature = "listen")]
use crate::client::{ListenOptions, WebSocketHandle};

use super::{
    bearer_prefix, encode_account_signature, encode_device_signature,
};

/// Client that can synchronize with a server over HTTP(S).
#[derive(Clone)]
pub struct HttpClient {
    origin: Origin,
    account_signer: BoxedEcdsaSigner,
    device_signer: BoxedEd25519Signer,
    client: reqwest::Client,
    connection_id: String,
}

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
        origin: Origin,
        account_signer: BoxedEcdsaSigner,
        device_signer: BoxedEd25519Signer,
        connection_id: String,
    ) -> Result<Self> {
        let client = reqwest::ClientBuilder::new()
            .read_timeout(Duration::from_millis(15000))
            .connect_timeout(Duration::from_millis(5000))
            .build()?;
        Ok(Self {
            origin,
            account_signer,
            device_signer,
            client,
            connection_id,
        })
    }

    /// Account signing key.
    pub fn account_signer(&self) -> &BoxedEcdsaSigner {
        &self.account_signer
    }

    /// Device signing key.
    pub fn device_signer(&self) -> &BoxedEd25519Signer {
        &self.device_signer
    }

    /// Spawn a thread that listens for changes
    /// from the remote server using a websocket
    /// that performs automatic re-connection.
    #[cfg(feature = "listen")]
    pub(crate) fn listen<F>(
        &self,
        options: ListenOptions,
        handler: impl Fn(ChangeNotification) -> F + Send + Sync + 'static,
    ) -> WebSocketHandle
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let listener = WebSocketChangeListener::new(
            self.origin.clone(),
            self.account_signer.clone(),
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
        let sos_type = HeaderValue::from_static(MIME_TYPE_SOS);
        let status = response.status();
        let content_type = response.headers().get(&header::CONTENT_TYPE);
        match (status, content_type) {
            // OK with the correct MIME type can be handled
            (http::StatusCode::OK, Some(content_type)) => {
                if content_type == &sos_type {
                    Ok(response)
                } else {
                    Err(Error::ContentType(
                        content_type.to_str()?.to_owned(),
                        MIME_TYPE_SOS.to_string(),
                    ))
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
        let json_type = HeaderValue::from_static("application/json");
        let content_type = response.headers().get(&header::CONTENT_TYPE);
        if !status.is_success() {
            if let Some(content_type) = content_type {
                if content_type == json_type {
                    let value: Value = response.json().await?;
                    Err(Error::ResponseJson(status, value))
                } else {
                    Err(Error::ResponseCode(status))
                }
            } else {
                Ok(response)
            }
        } else {
            Ok(response)
        }
    }
}

#[async_trait]
impl SyncClient for HttpClient {
    fn origin(&self) -> &Origin {
        &self.origin
    }

    #[instrument(skip(self, account))]
    async fn create_account(&self, account: &ChangeSet) -> Result<()> {
        let body = encode(account).await?;
        let url = self.build_url("api/v1/sync/account")?;

        tracing::debug!(url = %url, "http::create_account");

        let account_signature =
            encode_account_signature(self.account_signer.sign(&body).await?)
                .await?;
        let auth = bearer_prefix(&account_signature, None);
        let response = self
            .client
            .put(url)
            .header(AUTHORIZATION, auth)
            .body(body)
            .send()
            .await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::create_account");
        self.error_json(response).await?;
        Ok(())
    }

    #[instrument(skip(self, account))]
    async fn update_account(&self, account: &UpdateSet) -> Result<()> {
        let body = encode(account).await?;
        let url = self.build_url("api/v1/sync/account")?;

        tracing::debug!(url = %url, "http::update_account");

        let account_signature =
            encode_account_signature(self.account_signer.sign(&body).await?)
                .await?;
        let device_signature =
            encode_device_signature(self.device_signer.sign(&body).await?)
                .await?;
        let auth = bearer_prefix(&account_signature, Some(&device_signature));
        let response = self
            .client
            .post(url)
            .header(AUTHORIZATION, auth)
            .body(body)
            .send()
            .await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::update_account");
        self.error_json(response).await?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn fetch_account(&self) -> Result<ChangeSet> {
        let url = self.build_url("api/v1/sync/account")?;

        tracing::debug!(url = %url, "http::fetch_account");

        let sign_url = url.path();
        let account_signature = encode_account_signature(
            self.account_signer.sign(sign_url.as_bytes()).await?,
        )
        .await?;
        let device_signature = encode_device_signature(
            self.device_signer.sign(sign_url.as_bytes()).await?,
        )
        .await?;
        let auth = bearer_prefix(&account_signature, Some(&device_signature));
        let response = self
            .client
            .get(url)
            .header(AUTHORIZATION, auth)
            .send()
            .await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::fetch_account");
        let response = self.check_response(response).await?;
        let buffer = response.bytes().await?;
        Ok(decode(&buffer).await?)
    }

    #[instrument(skip(self))]
    async fn sync_status(&self) -> Result<Option<SyncStatus>> {
        let url = self.build_url("api/v1/sync/account/status")?;

        tracing::debug!(url = %url, "http::sync_status");

        let sign_url = url.path();
        let account_signature = encode_account_signature(
            self.account_signer.sign(sign_url.as_bytes()).await?,
        )
        .await?;
        let device_signature = encode_device_signature(
            self.device_signer.sign(sign_url.as_bytes()).await?,
        )
        .await?;
        let auth = bearer_prefix(&account_signature, Some(&device_signature));
        let response = self
            .client
            .get(url)
            .header(AUTHORIZATION, auth)
            .send()
            .await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::sync_status");
        let response = self.check_response(response).await?;
        let buffer = response.bytes().await?;
        let sync_status: Option<SyncStatus> = decode(&buffer).await?;
        Ok(sync_status)
    }

    #[instrument(skip(self, packet))]
    async fn sync(&self, packet: &SyncPacket) -> Result<SyncPacket> {
        let body = encode(packet).await?;
        let url = self.build_url("api/v1/sync/account")?;

        tracing::debug!(url = %url, "http::sync");

        let account_signature =
            encode_account_signature(self.account_signer.sign(&body).await?)
                .await?;
        let device_signature =
            encode_device_signature(self.device_signer.sign(&body).await?)
                .await?;
        let auth = bearer_prefix(&account_signature, Some(&device_signature));
        let response = self
            .client
            .patch(url)
            .header(AUTHORIZATION, auth)
            .body(body)
            .send()
            .await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::sync");
        let response = self.check_response(response).await?;
        let buffer = response.bytes().await?;
        Ok(decode(&buffer).await?)
    }

    #[cfg(feature = "device")]
    #[instrument(skip(self, diff))]
    async fn patch_devices(&self, diff: &DeviceDiff) -> Result<()> {
        let body = encode(diff).await?;
        let url = self.build_url("api/v1/sync/account/devices")?;

        tracing::debug!(url = %url, "http::patch_devices");

        let account_signature =
            encode_account_signature(self.account_signer.sign(&body).await?)
                .await?;

        let device_signature =
            encode_device_signature(self.device_signer.sign(&body).await?)
                .await?;
        let auth = bearer_prefix(&account_signature, Some(&device_signature));
        let response = self
            .client
            .patch(url)
            .header(AUTHORIZATION, auth)
            .body(body)
            .send()
            .await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::patch_devices");
        self.error_json(response).await?;
        Ok(())
    }

    #[cfg(feature = "files")]
    #[instrument(skip(self, path, progress))]
    async fn upload_file(
        &self,
        file_info: &ExternalFile,
        path: &Path,
        progress: Arc<ProgressChannel>,
        mut cancel: tokio::sync::mpsc::Receiver<()>,
    ) -> Result<http::StatusCode> {
        use crate::sdk::vfs;
        use reqwest::{
            header::{CONTENT_LENGTH, CONTENT_TYPE},
            Body,
        };
        use tokio_util::io::ReaderStream;

        let url_path = format!("api/v1/sync/file/{}", file_info);
        let url = self.build_url(&url_path)?;

        tracing::debug!(url = %url, "http::upload_file");

        let sign_url = url.path();
        let account_signature = encode_account_signature(
            self.account_signer.sign(sign_url.as_bytes()).await?,
        )
        .await?;
        let device_signature = encode_device_signature(
            self.device_signer.sign(sign_url.as_bytes()).await?,
        )
        .await?;
        let auth = bearer_prefix(&account_signature, Some(&device_signature));

        let metadata = vfs::metadata(path).await?;
        let file_size = metadata.len();
        let file = vfs::File::open(path).await?;

        let mut bytes_sent = 0;
        let _ = progress.send((bytes_sent, Some(file_size)));

        let mut reader_stream = ReaderStream::new(file);
        let progress_stream = async_stream::stream! {
            loop {
              tokio::select! {
                biased;
                _ = cancel.recv() => {
                  yield Err(Error::TransferCanceled);
                }
                Some(chunk) = reader_stream.next() => {
                  if let Ok(bytes) = &chunk {
                      bytes_sent += bytes.len() as u64;
                      let _ = progress.send((bytes_sent, Some(file_size)));
                  }
                  yield chunk.map_err(Error::from);
                }
              }
            }
        };

        let response = self
            .client
            .put(url)
            .header(AUTHORIZATION, auth)
            .header(CONTENT_LENGTH, file_size)
            .header(CONTENT_TYPE, "application/octet-stream")
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

    #[cfg(feature = "files")]
    #[instrument(skip(self, path, progress))]
    async fn download_file(
        &self,
        file_info: &ExternalFile,
        path: &Path,
        progress: Arc<ProgressChannel>,
        mut cancel: tokio::sync::mpsc::Receiver<()>,
    ) -> Result<http::StatusCode> {
        use crate::sdk::vfs;
        use tokio::io::AsyncWriteExt;

        let url_path = format!("api/v1/sync/file/{}", file_info);
        let url = self.build_url(&url_path)?;

        tracing::debug!(url = %url, "http::download_file");

        let sign_url = url.path();
        let account_signature = encode_account_signature(
            self.account_signer.sign(sign_url.as_bytes()).await?,
        )
        .await?;
        let device_signature = encode_device_signature(
            self.device_signer.sign(sign_url.as_bytes()).await?,
        )
        .await?;
        let auth = bearer_prefix(&account_signature, Some(&device_signature));

        let mut response = self
            .client
            .get(url)
            .header(AUTHORIZATION, auth)
            .send()
            .await?;

        let file_size = response.content_length();
        let mut bytes_received = 0;
        let _ = progress.send((bytes_received, file_size));

        let mut hasher = Sha256::new();
        let mut file = vfs::File::create(path).await?;

        loop {
            tokio::select! {
                _ = cancel.recv() => {
                  vfs::remove_file(path).await?;
                  return Err(Error::TransferCanceled);
                }
                chunk = response.chunk() => {
                  if let Some(chunk) = chunk? {
                    file.write_all(&chunk).await?;
                    hasher.update(&chunk);

                    bytes_received += chunk.len() as u64;
                    let _ = progress.send((bytes_received, file_size));
                  } else {
                    break;
                  }
                }
            }
        }

        file.flush().await?;
        let digest = hasher.finalize();

        if digest.as_slice() != file_info.file_name().as_ref() {
            tokio::fs::remove_file(path).await?;
            return Err(Error::FileChecksumMismatch(
                file_info.file_name().to_string(),
                hex::encode(digest.as_slice()),
            ));
        }
        let status = response.status();
        tracing::debug!(status = %status, "http::download_file");
        self.error_json(response).await?;
        Ok(status)
    }

    #[cfg(feature = "files")]
    #[instrument(skip(self))]
    async fn delete_file(
        &self,
        file_info: &ExternalFile,
    ) -> Result<http::StatusCode> {
        let url_path = format!("api/v1/sync/file/{}", file_info);
        let url = self.build_url(&url_path)?;

        tracing::debug!(url = %url, "http::delete_file");

        let sign_url = url.path();
        let account_signature = encode_account_signature(
            self.account_signer.sign(sign_url.as_bytes()).await?,
        )
        .await?;
        let device_signature = encode_device_signature(
            self.device_signer.sign(sign_url.as_bytes()).await?,
        )
        .await?;
        let auth = bearer_prefix(&account_signature, Some(&device_signature));

        let response = self
            .client
            .delete(url)
            .header(AUTHORIZATION, auth)
            .send()
            .await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::delete_file");
        if !status.is_success() && status != http::StatusCode::NOT_FOUND {
            self.error_json(response).await?;
        }
        Ok(status)
    }

    #[cfg(feature = "files")]
    #[instrument(skip(self))]
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

        let sign_url = url.path();
        let account_signature = encode_account_signature(
            self.account_signer.sign(sign_url.as_bytes()).await?,
        )
        .await?;
        let device_signature = encode_device_signature(
            self.device_signer.sign(sign_url.as_bytes()).await?,
        )
        .await?;

        let auth = bearer_prefix(&account_signature, Some(&device_signature));

        let response = self
            .client
            .post(url)
            .header(AUTHORIZATION, auth)
            .send()
            .await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::move_file");
        self.error_json(response).await?;
        Ok(status)
    }

    #[instrument(skip(self, local_files))]
    async fn compare_files(
        &self,
        local_files: &FileSet,
    ) -> Result<FileTransfersSet> {
        let url_path = format!("api/v1/sync/files");
        let url = self.build_url(&url_path)?;

        tracing::debug!(url = %url, "http::compare_files");

        let sign_url = url.path();
        let account_signature = encode_account_signature(
            self.account_signer.sign(sign_url.as_bytes()).await?,
        )
        .await?;
        let device_signature = encode_device_signature(
            self.device_signer.sign(sign_url.as_bytes()).await?,
        )
        .await?;
        let auth = bearer_prefix(&account_signature, Some(&device_signature));

        let body = encode(local_files).await?;

        let response = self
            .client
            .post(url)
            .header(AUTHORIZATION, auth)
            .body(body)
            .send()
            .await?;
        let status = response.status();
        tracing::debug!(status = %status, "http::compare_files");
        let response = self.check_response(response).await?;
        let buffer = response.bytes().await?;
        Ok(decode(&buffer).await?)
    }
}
