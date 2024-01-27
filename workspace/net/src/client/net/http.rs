//! HTTP client implementation.
use async_trait::async_trait;
use futures::{Future, StreamExt};
use reqwest::header::AUTHORIZATION;
use sos_sdk::{
    constants::MIME_TYPE_SOS,
    decode, encode,
    sha2::{Digest, Sha256},
    signer::{ecdsa::BoxedEcdsaSigner, ed25519::BoxedEd25519Signer},
    sync::{ChangeSet, Origin, SyncClient, SyncPacket, SyncStatus},
};

use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tracing::{span, Level};

#[cfg(feature = "listen")]
use crate::ChangeNotification;

#[cfg(feature = "listen")]
use super::websocket::WebSocketChangeListener;

#[cfg(feature = "device")]
use crate::sdk::sync::DeviceDiff;

#[cfg(feature = "files")]
use crate::sdk::storage::files::{
    ExternalFile, FileSet, FileTransfersSet, InflightTransfer,
};

use std::path::PathBuf;
use url::Url;

use crate::client::{Error, Result};

#[cfg(feature = "listen")]
use crate::client::{ListenOptions, WebSocketHandle};

use super::{
    bearer_prefix, encode_account_signature, encode_device_signature,
};

// Hack for incompatible http types as reqwest is currently
// using an old version of HTTP.
//
// Once reqwest ships with http@1 we can remove this hack.
fn convert_status_code(value: reqwest::StatusCode) -> http::StatusCode {
    http::StatusCode::from_u16(value.as_u16()).unwrap()
}

/// Client that can synchronize with a server over HTTP(S).
#[derive(Clone)]
pub struct HttpClient {
    origin: Origin,
    account_signer: BoxedEcdsaSigner,
    device_signer: BoxedEd25519Signer,
    client: reqwest::Client,
    connection_id: String,
}

impl HttpClient {
    /// Create a new client.
    pub fn new(
        origin: Origin,
        account_signer: BoxedEcdsaSigner,
        device_signer: BoxedEd25519Signer,
        connection_id: String,
    ) -> Result<Self> {
        let client = reqwest::Client::new();
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
        let status = convert_status_code(response.status());
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

        let status = convert_status_code(response.status());
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
    type Error = Error;

    /*
    fn url(&self) -> &Url {
        self.origin.url()
    }
    */

    fn origin(&self) -> &Origin {
        &self.origin
    }

    async fn create_account(&self, account: &ChangeSet) -> Result<()> {
        let span = span!(Level::DEBUG, "create_account");
        let _enter = span.enter();

        let body = encode(account).await?;
        let url = self.build_url("api/v1/sync/account")?;
        let account_signature =
            encode_account_signature(self.account_signer.sign(&body).await?)
                .await?;
        let auth = bearer_prefix(&account_signature, None);
        let response = self
            .client
            .post(url)
            .header(AUTHORIZATION, auth)
            .body(body)
            .send()
            .await?;
        let status = convert_status_code(response.status());
        tracing::debug!(status = %status);
        self.error_json(response).await?;
        Ok(())
    }

    async fn fetch_account(
        &self,
    ) -> std::result::Result<ChangeSet, Self::Error> {
        let span = span!(Level::DEBUG, "fetch_account");
        let _enter = span.enter();

        let url = self.build_url("api/v1/sync/account")?;
        let sign_url = url.path();
        let account_signature = encode_account_signature(
            self.account_signer.sign(sign_url.as_bytes()).await?,
        )
        .await?;
        let auth = bearer_prefix(&account_signature, None);
        let response = self
            .client
            .get(url)
            .header(AUTHORIZATION, auth)
            .send()
            .await?;
        let status = convert_status_code(response.status());
        tracing::debug!(status = %status);
        let response = self.check_response(response).await?;
        let buffer = response.bytes().await?;
        Ok(decode(&buffer).await?)
    }

    async fn sync_status(&self) -> Result<Option<SyncStatus>> {
        let span = span!(Level::DEBUG, "sync_status");
        let _enter = span.enter();

        let url = self.build_url("api/v1/sync/account/status")?;
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
        let status = convert_status_code(response.status());
        tracing::debug!(status = %status);
        let response = self.check_response(response).await?;
        let buffer = response.bytes().await?;
        let sync_status: Option<SyncStatus> = decode(&buffer).await?;
        Ok(sync_status)
    }

    async fn sync(
        &self,
        packet: &SyncPacket,
    ) -> std::result::Result<SyncPacket, Self::Error> {
        let span = span!(Level::DEBUG, "sync_account");
        let _enter = span.enter();

        let body = encode(packet).await?;
        let url = self.build_url("api/v1/sync/account")?;
        let account_signature =
            encode_account_signature(self.account_signer.sign(&body).await?)
                .await?;
        let device_signature =
            encode_device_signature(self.device_signer.sign(&body).await?)
                .await?;
        let auth = bearer_prefix(&account_signature, Some(&device_signature));
        let response = self
            .client
            .put(url)
            .header(AUTHORIZATION, auth)
            .body(body)
            .send()
            .await?;
        let status = convert_status_code(response.status());
        tracing::debug!(status = %status);
        let response = self.check_response(response).await?;
        let buffer = response.bytes().await?;
        Ok(decode(&buffer).await?)
    }

    #[cfg(feature = "device")]
    async fn patch_devices(
        &self,
        diff: &DeviceDiff,
    ) -> std::result::Result<(), Self::Error> {
        let span = span!(Level::DEBUG, "patch_devices");
        let _enter = span.enter();

        let body = encode(diff).await?;
        let url = self.build_url("api/v1/sync/account/devices")?;
        let account_signature =
            encode_account_signature(self.account_signer.sign(&body).await?)
                .await?;
        let auth = bearer_prefix(&account_signature, None);
        let response = self
            .client
            .patch(url)
            .header(AUTHORIZATION, auth)
            .body(body)
            .send()
            .await?;
        let status = convert_status_code(response.status());
        tracing::debug!(status = %status);
        self.error_json(response).await?;
        Ok(())
    }

    #[cfg(feature = "files")]
    async fn upload_file(
        &self,
        file_info: &ExternalFile,
        path: &PathBuf,
        inflight_transfer: InflightTransfer,
    ) -> std::result::Result<http::StatusCode, Self::Error> {
        use crate::sdk::vfs;
        use reqwest::{
            header::{CONTENT_LENGTH, CONTENT_TYPE},
            Body,
        };
        use tokio_util::io::ReaderStream;

        let span = span!(Level::DEBUG, "upload_file");
        let _enter = span.enter();
        tracing::debug!(file = %file_info);

        let url_path = format!("api/v1/sync/file/{}", file_info);
        let url = self.build_url(&url_path)?;
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

        {
            let mut writer = inflight_transfer.write().await;
            writer.bytes_total = file_size;
        }

        let mut reader_stream = ReaderStream::new(file);
        let progress_stream = async_stream::stream! {
            while let Some(chunk) = reader_stream.next().await {
                if let Ok(bytes) = &chunk {
                    let mut writer = inflight_transfer.write().await;
                    writer.bytes_transferred += bytes.len() as u64;
                }
                yield chunk;
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
        let status = convert_status_code(response.status());
        tracing::debug!(status = %status);
        if !status.is_success() && status != http::StatusCode::NOT_MODIFIED {
            self.error_json(response).await?;
        }
        Ok(status)
    }

    #[cfg(feature = "files")]
    async fn download_file(
        &self,
        file_info: &ExternalFile,
        path: &PathBuf,
        inflight_transfer: InflightTransfer,
    ) -> std::result::Result<http::StatusCode, Self::Error> {
        use crate::sdk::vfs;

        let span = span!(Level::DEBUG, "download_file");
        let _enter = span.enter();
        tracing::debug!(file = %file_info);

        let url_path = format!("api/v1/sync/file/{}", file_info);
        let url = self.build_url(&url_path)?;
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

        if let Some(len) = response.content_length() {
            let mut writer = inflight_transfer.write().await;
            writer.bytes_total = len;
        }

        let mut hasher = Sha256::new();
        let mut file = vfs::File::create(path).await?;
        while let Some(chunk) = response.chunk().await? {
            file.write_all(&chunk).await?;
            hasher.update(&chunk);

            let mut writer = inflight_transfer.write().await;
            writer.bytes_transferred += chunk.len() as u64;
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
        let status = convert_status_code(response.status());
        tracing::debug!(status = %status);
        self.error_json(response).await?;
        Ok(status)
    }

    #[cfg(feature = "files")]
    async fn delete_file(
        &self,
        file_info: &ExternalFile,
    ) -> std::result::Result<http::StatusCode, Self::Error> {
        let span = span!(Level::DEBUG, "delete_file");
        let _enter = span.enter();
        tracing::debug!(file = %file_info);

        let url_path = format!("api/v1/sync/file/{}", file_info);
        let url = self.build_url(&url_path)?;
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
        let status = convert_status_code(response.status());
        tracing::debug!(status = %status);
        if !status.is_success() && status != http::StatusCode::NOT_FOUND {
            self.error_json(response).await?;
        }
        Ok(status)
    }

    #[cfg(feature = "files")]
    async fn move_file(
        &self,
        from: &ExternalFile,
        to: &ExternalFile,
    ) -> std::result::Result<http::StatusCode, Self::Error> {
        let span = span!(Level::DEBUG, "move_file");
        let _enter = span.enter();
        tracing::debug!(from = %from, to = %to);

        let url_path = format!("api/v1/sync/file/{}", from);
        let mut url = self.build_url(&url_path)?;
        url.query_pairs_mut()
            .append_pair("vault_id", &to.vault_id().to_string())
            .append_pair("secret_id", &to.secret_id().to_string())
            .append_pair("name", &to.file_name().to_string());
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
        let status = convert_status_code(response.status());
        tracing::debug!(status = %status);
        self.error_json(response).await?;
        Ok(status)
    }

    async fn compare_files(
        &self,
        local_files: &FileSet,
    ) -> std::result::Result<FileTransfersSet, Self::Error> {
        let span = span!(Level::DEBUG, "compare_files");
        let _enter = span.enter();

        let url_path = format!("api/v1/sync/files");
        let url = self.build_url(&url_path)?;
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
        let status = convert_status_code(response.status());
        tracing::debug!(status = %status);
        let response = self.check_response(response).await?;
        let buffer = response.bytes().await?;
        Ok(decode(&buffer).await?)
    }
}
