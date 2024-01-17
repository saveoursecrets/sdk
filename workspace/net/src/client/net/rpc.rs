//! Remote procedure call (RPC) client implementation.
use async_trait::async_trait;
use futures::Future;
use reqwest::header::{self, HeaderValue, AUTHORIZATION};
use serde::de::DeserializeOwned;
use serde_json::Value;
use sos_sdk::{
    constants::{
        ACCOUNT_CREATE, ACCOUNT_FETCH, DEVICE_PATCH, MIME_TYPE_RPC,
        SYNC_RESOLVE, SYNC_STATUS,
    },
    decode, encode,
    sha2::{Digest, Sha256},
    signer::{ecdsa::BoxedEcdsaSigner, ed25519::BoxedEd25519Signer},
    sync::{ChangeSet, Origin, SyncClient, SyncDiff, SyncStatus},
};

use tokio::io::AsyncWriteExt;
use tracing::{span, Level};

#[cfg(feature = "listen")]
use crate::events::ChangeNotification;

#[cfg(feature = "listen")]
use super::websocket::WebSocketChangeListener;

#[cfg(feature = "device")]
use crate::sdk::sync::DeviceDiff;

#[cfg(feature = "files")]
use crate::sdk::storage::files::ExternalFile;

use std::{
    borrow::Cow,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tokio::sync::Mutex;
use url::Url;

use crate::{
    client::{Error, Result},
    rpc::{Packet, RequestMessage, ResponseMessage},
};

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

/// Client for the self-hosted server that
/// communicates using RPC messages.
#[derive(Clone)]
pub struct RpcClient {
    origin: Origin,
    account_signer: BoxedEcdsaSigner,
    device_signer: BoxedEd25519Signer,
    client: reqwest::Client,
    id: Arc<Mutex<AtomicU64>>,
    connection_id: String,
}

impl RpcClient {
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
            id: Arc::new(Mutex::new(AtomicU64::from(1))),
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

    /// Generic GET function.
    pub async fn get(url: Url) -> Result<reqwest::Response> {
        let client = reqwest::Client::new();
        Ok(client.get(url).send().await?)
    }

    /// Server information.
    pub async fn server_info(server: Url) -> Result<reqwest::Response> {
        let client = reqwest::Client::new();
        let url = server.join("api")?;
        Ok(client.get(url).send().await?)
    }

    /// Total number of websocket connections on remote.
    pub async fn num_connections(server: &Url) -> Result<usize> {
        let client = reqwest::Client::new();
        let url = server.join("api/connections")?;
        let res = client.get(url).send().await?;
        let res = res.error_for_status()?;
        let value = res.json::<usize>().await?;
        Ok(value)
    }

    /// Get the next request identifier.
    async fn next_id(&self) -> u64 {
        let id = self.id.lock().await;
        id.fetch_add(1, Ordering::SeqCst)
    }

    /// Build a URL including the connection identifier
    /// in the query string.
    fn build_url(&self, route: &str) -> Result<Url> {
        let mut url = self.origin.url.join(route)?;
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
        let json_type = HeaderValue::from_static("application/json");
        let rpc_type = HeaderValue::from_static(MIME_TYPE_RPC);
        let status = convert_status_code(response.status());
        let content_type = response.headers().get(&header::CONTENT_TYPE);
        match (status, content_type) {
            // OK with the correct MIME type can be handled
            (http::StatusCode::OK, Some(content_type)) => {
                if content_type == &rpc_type {
                    Ok(response)
                } else {
                    Err(Error::ResponseCode(status))
                }
            }
            // Otherwise exit out early
            _ => {
                if let Some(content_type) = content_type {
                    if content_type == json_type {
                        let value: Value = response.json().await?;
                        Err(Error::ResponseJson(status, value))
                    } else {
                        Err(Error::ResponseCode(status))
                    }
                } else {
                    Err(Error::ResponseCode(status))
                }
            }
        }
    }

    /// Try to create a new account.
    async fn try_create_account(
        &self,
        account: &ChangeSet,
    ) -> Result<http::StatusCode> {
        let url = self.build_url("api/account")?;

        let id = self.next_id().await;
        let body = encode(account).await?;
        let request = RequestMessage::new(
            Some(id),
            ACCOUNT_CREATE,
            (),
            Cow::Owned(body),
        )?;
        let packet = Packet::new_request(request);
        let body = encode(&packet).await?;
        let account_signature =
            encode_account_signature(self.account_signer.sign(&body).await?)
                .await?;

        let response = self
            .send_request(url, body, account_signature, None)
            .await?;
        let response = self.check_response(response).await?;
        let (status, _, _) = self
            .read_response::<()>(
                convert_status_code(response.status()),
                &response.bytes().await?,
            )
            .await?;
        Ok(status)
    }

    /// Try to fetch an existing account.
    async fn try_fetch_account(&self) -> Result<(http::StatusCode, Vec<u8>)> {
        let url = self.build_url("api/account")?;

        let id = self.next_id().await;
        let request = RequestMessage::new_call(Some(id), ACCOUNT_FETCH, ())?;
        let packet = Packet::new_request(request);
        let body = encode(&packet).await?;
        let account_signature =
            encode_account_signature(self.account_signer.sign(&body).await?)
                .await?;

        let response = self
            .send_request(url, body, account_signature, None)
            .await?;
        let response = self.check_response(response).await?;
        let (status, _, body) = self
            .read_response::<()>(
                convert_status_code(response.status()),
                &response.bytes().await?,
            )
            .await?;
        Ok((status, body))
    }

    /// Try to patch the event log on remote.
    async fn try_patch_devices(
        &self,
        diff: &DeviceDiff,
    ) -> Result<http::StatusCode> {
        let url = self.build_url("api/account")?;

        let id = self.next_id().await;
        let body = encode(diff).await?;
        let request = RequestMessage::new(
            Some(id),
            DEVICE_PATCH,
            (),
            Cow::Owned(body),
        )?;

        let packet = Packet::new_request(request);
        let body = encode(&packet).await?;
        let account_signature =
            encode_account_signature(self.account_signer.sign(&body).await?)
                .await?;

        let response = self
            .send_request(url, body, account_signature, None)
            .await?;
        let response = self.check_response(response).await?;
        let (status, _, _) = self
            .read_response::<()>(
                convert_status_code(response.status()),
                &response.bytes().await?,
            )
            .await?;

        Ok(status)
    }

    /// Try to sync status on remote.
    async fn try_sync_status(
        &self,
    ) -> Result<(http::StatusCode, Option<SyncStatus>)> {
        let url = self.build_url("api/account")?;

        let id = self.next_id().await;
        let request = RequestMessage::new_call(Some(id), SYNC_STATUS, ())?;
        let packet = Packet::new_request(request);
        let body = encode(&packet).await?;
        let account_signature =
            encode_account_signature(self.account_signer.sign(&body).await?)
                .await?;
        let device_signature =
            encode_device_signature(self.device_signer.sign(&body).await?)
                .await?;

        let response = self
            .send_request(
                url,
                body,
                account_signature,
                Some(device_signature),
            )
            .await?;
        let response = self.check_response(response).await?;
        let (status, result, _) = self
            .read_response::<Option<SyncStatus>>(
                convert_status_code(response.status()),
                &response.bytes().await?,
            )
            .await?;

        Ok((status, result?))
    }

    /// Try to sync with a remote.
    async fn try_sync(
        &self,
        local_status: &SyncStatus,
        diff: &SyncDiff,
    ) -> Result<(http::StatusCode, Vec<u8>)> {
        let url = self.build_url("api/sync")?;

        let id = self.next_id().await;
        let body = encode(diff).await?;
        let request = RequestMessage::new(
            Some(id),
            SYNC_RESOLVE,
            &local_status,
            Cow::Owned(body),
        )?;

        let packet = Packet::new_request(request);
        let body = encode(&packet).await?;
        let account_signature =
            encode_account_signature(self.account_signer.sign(&body).await?)
                .await?;
        let device_signature =
            encode_device_signature(self.device_signer.sign(&body).await?)
                .await?;

        let response = self
            .send_request(
                url,
                body,
                account_signature,
                Some(device_signature),
            )
            .await?;
        let response = self.check_response(response).await?;
        let (status, _, body) = self
            .read_response::<SyncStatus>(
                convert_status_code(response.status()),
                &response.bytes().await?,
            )
            .await?;
        Ok((status, body))
    }

    /// Try to send a file to remote.
    ///
    /// Files are already encrypted so no sensitive information is leaked
    /// although this could make us more vulnerable to MitM or replay attacks
    /// when the backend server is not using TLS.
    #[cfg(feature = "files")]
    async fn try_upload_file(
        &self,
        file_info: &ExternalFile,
        path: &PathBuf,
    ) -> Result<http::StatusCode> {
        use crate::sdk::vfs;
        use reqwest::{
            header::{CONTENT_LENGTH, CONTENT_TYPE},
            Body,
        };
        use tokio_util::io::ReaderStream;

        // For this request we sign the request path
        // bytes that encode the file name information
        let signed_data = file_info.to_string();
        let account_signature = encode_account_signature(
            self.account_signer.sign(signed_data.as_bytes()).await?,
        )
        .await?;
        let device_signature = encode_device_signature(
            self.device_signer.sign(signed_data.as_bytes()).await?,
        )
        .await?;
        let auth = bearer_prefix(&account_signature, Some(&device_signature));

        let url_path = format!("api/file/{}", signed_data);
        let url = self.build_url(&url_path)?;
        let metadata = vfs::metadata(path).await?;
        let file_size = metadata.len();

        let file = vfs::File::open(path).await?;
        let stream = ReaderStream::new(file);

        let response = self
            .client
            .put(url)
            .header(AUTHORIZATION, auth)
            .header(CONTENT_LENGTH, file_size)
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(Body::wrap_stream(stream))
            .send()
            .await?;
        Ok(convert_status_code(response.status()))
    }

    /// Try to receive a file from remote.
    #[cfg(feature = "files")]
    async fn try_download_file(
        &self,
        file_info: &ExternalFile,
        path: &PathBuf,
    ) -> Result<http::StatusCode> {
        use crate::sdk::vfs;

        // For this request we sign the request path
        // bytes that encode the file name information
        let signed_data = file_info.to_string();
        let account_signature = encode_account_signature(
            self.account_signer.sign(signed_data.as_bytes()).await?,
        )
        .await?;
        let device_signature = encode_device_signature(
            self.device_signer.sign(signed_data.as_bytes()).await?,
        )
        .await?;
        let auth = bearer_prefix(&account_signature, Some(&device_signature));

        let url_path = format!("api/file/{}", signed_data);
        let url = self.build_url(&url_path)?;

        let mut response = self
            .client
            .get(url)
            .header(AUTHORIZATION, auth)
            .send()
            .await?;
        let mut hasher = Sha256::new();
        let mut file = vfs::File::create(path).await?;
        while let Some(chunk) = response.chunk().await? {
            file.write_all(&chunk).await?;
            hasher.update(&chunk);
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

        Ok(convert_status_code(response.status()))
    }

    /// Try to delete a file on remote.
    #[cfg(feature = "files")]
    async fn try_delete_file(
        &self,
        file_info: &ExternalFile,
    ) -> Result<http::StatusCode> {
        // For this request we sign the request path
        // bytes that encode the file name information
        let signed_data = file_info.to_string();
        let account_signature = encode_account_signature(
            self.account_signer.sign(signed_data.as_bytes()).await?,
        )
        .await?;
        let device_signature = encode_device_signature(
            self.device_signer.sign(signed_data.as_bytes()).await?,
        )
        .await?;
        let auth = bearer_prefix(&account_signature, Some(&device_signature));

        let url_path = format!("api/file/{}", signed_data);
        let url = self.build_url(&url_path)?;

        let response = self
            .client
            .delete(url)
            .header(AUTHORIZATION, auth)
            .send()
            .await?;
        Ok(convert_status_code(response.status()))
    }

    /// Try to move a file on remote.
    #[cfg(feature = "files")]
    async fn try_move_file(
        &self,
        from: &ExternalFile,
        to: &ExternalFile,
    ) -> Result<http::StatusCode> {
        // For this request we sign the request path
        // bytes that encode the file name information
        let signed_data = from.to_string();
        let account_signature = encode_account_signature(
            self.account_signer.sign(signed_data.as_bytes()).await?,
        )
        .await?;
        let device_signature = encode_device_signature(
            self.device_signer.sign(signed_data.as_bytes()).await?,
        )
        .await?;

        let auth = bearer_prefix(&account_signature, Some(&device_signature));
        let url_path = format!("api/file/{}", signed_data);
        let mut url = self.build_url(&url_path)?;
        url.query_pairs_mut()
            .append_pair("vault_id", &to.vault_id().to_string())
            .append_pair("secret_id", &to.secret_id().to_string())
            .append_pair("name", &to.file_name().to_string());

        let response = self
            .client
            .post(url)
            .header(AUTHORIZATION, auth)
            .send()
            .await?;
        Ok(convert_status_code(response.status()))
    }

    /// Send an encrypted session request.
    async fn send_request(
        &self,
        url: Url,
        body: Vec<u8>,
        account_signature: String,
        device_signature: Option<String>,
    ) -> Result<reqwest::Response> {
        let auth = if let Some(device_signature) = &device_signature {
            bearer_prefix(&account_signature, Some(device_signature))
        } else {
            bearer_prefix(&account_signature, None)
        };
        let response = self
            .client
            .post(url)
            .header(AUTHORIZATION, auth)
            .body(body)
            .send()
            .await?;
        Ok(response)
    }

    /// Read a response to an RPC call.
    async fn read_response<T: DeserializeOwned>(
        &self,
        http_status: http::StatusCode,
        buffer: &[u8],
    ) -> Result<(http::StatusCode, crate::rpc::Result<T>, Vec<u8>)> {
        if http_status.is_success() {
            let reply: Packet<'static> = decode(buffer).await?;
            let response: ResponseMessage<'static> = reply.try_into()?;
            let (_, status, result, body) = response.take::<T>()?;
            let result = result.ok_or(Error::NoReturnValue)?;
            Ok((status, result, body))
        } else {
            Err(Error::ResponseCode(http_status))
        }
    }
}

#[async_trait]
impl SyncClient for RpcClient {
    type Error = Error;

    fn url(&self) -> &Url {
        &self.origin.url
    }

    async fn create_account(&self, account: &ChangeSet) -> Result<()> {
        let span = span!(Level::DEBUG, "create_account");
        let _enter = span.enter();
        let status = self.try_create_account(account).await?;
        tracing::debug!(status = %status);
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status))?;
        Ok(())
    }

    async fn fetch_account(
        &self,
    ) -> std::result::Result<ChangeSet, Self::Error> {
        let span = span!(Level::DEBUG, "fetch_account");
        let _enter = span.enter();
        let (status, body) = self.try_fetch_account().await?;
        tracing::debug!(status = %status);
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status))?;
        Ok(decode(&body).await?)
    }

    async fn sync_status(&self) -> Result<Option<SyncStatus>> {
        let (_, value) = self.try_sync_status().await?;
        Ok(value)
    }

    async fn sync(
        &self,
        local_status: &SyncStatus,
        diff: &SyncDiff,
    ) -> std::result::Result<SyncDiff, Self::Error> {
        let (status, body) = self.try_sync(local_status, diff).await?;
        tracing::debug!(status = %status);
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status))?;
        Ok(decode(&body).await?)
    }

    #[cfg(feature = "device")]
    async fn patch_devices(
        &self,
        diff: &DeviceDiff,
    ) -> std::result::Result<(), Self::Error> {
        let span = span!(Level::DEBUG, "patch_devices");
        let _enter = span.enter();
        let status = self.try_patch_devices(diff).await?;
        tracing::debug!(status = %status);
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status))?;
        Ok(())
    }

    #[cfg(feature = "files")]
    async fn upload_file(
        &self,
        file_info: &ExternalFile,
        path: &PathBuf,
    ) -> std::result::Result<http::StatusCode, Self::Error> {
        let span = span!(Level::DEBUG, "upload_file");
        let _enter = span.enter();
        tracing::debug!(file = %file_info);
        let status = self.try_upload_file(file_info, path).await?;
        tracing::debug!(status = %status);
        Ok(status)
    }

    #[cfg(feature = "files")]
    async fn download_file(
        &self,
        file_info: &ExternalFile,
        path: &PathBuf,
    ) -> std::result::Result<http::StatusCode, Self::Error> {
        let span = span!(Level::DEBUG, "download_file");
        let _enter = span.enter();
        tracing::debug!(file = %file_info);
        let status = self.try_download_file(file_info, path).await?;
        tracing::debug!(status = %status);
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
        let status = self.try_delete_file(file_info).await?;
        tracing::debug!(status = %status);
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
        let status = self.try_move_file(from, to).await?;
        tracing::debug!(status = %status);
        Ok(status)
    }
}
