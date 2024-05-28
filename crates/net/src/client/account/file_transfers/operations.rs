//! File transfer operations.
//!
//! Tasks that handle retry until exhaustion for
//! download, upload, move and delete operations.
use crate::{
    client::{net::NetworkRetry, Error, Result, SyncClient},
    sdk::{storage::files::ExternalFile, vfs, Paths},
};

use async_recursion::async_recursion;
use http::StatusCode;
use std::{io::ErrorKind, sync::Arc};
use tokio::sync::watch;

use super::{
    notify_listeners, InflightNotification, InflightTransfers,
    ProgressChannel, TransferError, TransferResult,
};

pub struct UploadOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    client: C,
    paths: Arc<Paths>,
    request_id: u64,
    inflight: Arc<InflightTransfers>,
    retry: NetworkRetry,
}

impl<C> UploadOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    pub fn new(
        client: C,
        paths: Arc<Paths>,
        request_id: u64,
        inflight: Arc<InflightTransfers>,
        retry: NetworkRetry,
    ) -> Self {
        Self {
            client,
            paths,
            request_id,
            inflight,
            retry,
        }
    }

    #[async_recursion]
    pub async fn run(
        &self,
        file: ExternalFile,
        progress_tx: ProgressChannel,
        cancel_rx: watch::Receiver<()>,
    ) -> Result<TransferResult> {
        let path = self.paths.file_location(
            file.vault_id(),
            file.secret_id(),
            file.file_name().to_string(),
        );

        let result = match self
            .client
            .upload_file(&file, &path, progress_tx.clone(), cancel_rx.clone())
            .await
        {
            Ok(status) => self.on_response(status),
            Err(e) => self.on_error(e),
        };

        if let TransferResult::Retry = result {
            let retries = self.retry.increment().await;

            tracing::debug!(retries = %retries, "upload_file::retry");
            self.notify_retry(retries - 1, self.retry.maximum_retries)
                .await;

            if self.retry.is_exhausted(retries) {
                tracing::debug!(
                  maximum_retries = %self.retry.maximum_retries,
                  "upload_file::retries_exhausted");
                return Ok(TransferResult::Fatal(
                    TransferError::RetryExhausted,
                ));
            }

            self.retry
                .wait_and_retry(retries, async move {
                    self.run(file, progress_tx, cancel_rx).await
                })
                .await?
        } else {
            Ok(result)
        }
    }
}

impl<C> TransferTask for UploadOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    fn request_id(&self) -> u64 {
        self.request_id
    }

    fn inflight(&self) -> &InflightTransfers {
        &*self.inflight
    }

    fn on_response(&self, status: StatusCode) -> TransferResult {
        if status == StatusCode::OK || status == StatusCode::NOT_MODIFIED {
            TransferResult::Done
        } else {
            TransferResult::Retry
        }
    }

    fn on_error(&self, error: Error) -> TransferResult {
        tracing::warn!(error = ?error, "upload_file::error");
        on_error(error)
    }
}

pub struct DownloadOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    client: C,
    paths: Arc<Paths>,
    request_id: u64,
    inflight: Arc<InflightTransfers>,
    retry: NetworkRetry,
}

impl<C> DownloadOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    pub fn new(
        client: C,
        paths: Arc<Paths>,
        request_id: u64,
        inflight: Arc<InflightTransfers>,
        retry: NetworkRetry,
    ) -> Self {
        Self {
            client,
            paths,
            request_id,
            inflight,
            retry,
        }
    }

    #[async_recursion]
    pub async fn run(
        &self,
        file: ExternalFile,
        progress_tx: ProgressChannel,
        cancel_rx: watch::Receiver<()>,
    ) -> Result<TransferResult> {
        // Ensure the parent directory for the download exists
        let parent_path = self
            .paths
            .file_folder_location(file.vault_id())
            .join(file.secret_id().to_string());

        if !vfs::try_exists(&parent_path).await? {
            vfs::create_dir_all(&parent_path).await?;
        }

        // Fetch the file
        let path = self.paths.file_location(
            file.vault_id(),
            file.secret_id(),
            file.file_name().to_string(),
        );

        let result = match self
            .client
            .download_file(
                &file,
                &path,
                progress_tx.clone(),
                cancel_rx.clone(),
            )
            .await
        {
            Ok(status) => self.on_response(status),
            Err(e) => self.on_error(e),
        };

        if let TransferResult::Retry = result {
            let retries = self.retry.increment().await;

            tracing::debug!(retries = %retries, "download_file::retry");
            self.notify_retry(retries - 1, self.retry.maximum_retries)
                .await;

            if self.retry.is_exhausted(retries) {
                tracing::debug!(
                  maximum_retries = %self.retry.maximum_retries,
                  "download_file::retries_exhausted");
                return Ok(TransferResult::Fatal(
                    TransferError::RetryExhausted,
                ));
            }

            self.retry
                .wait_and_retry(retries, async move {
                    self.run(file, progress_tx, cancel_rx).await
                })
                .await?
        } else {
            Ok(result)
        }
    }
}

impl<C> TransferTask for DownloadOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    fn request_id(&self) -> u64 {
        self.request_id
    }

    fn inflight(&self) -> &InflightTransfers {
        &*self.inflight
    }

    fn on_response(&self, status: StatusCode) -> TransferResult {
        if status == StatusCode::OK {
            TransferResult::Done
        } else {
            TransferResult::Retry
        }
    }

    fn on_error(&self, error: Error) -> TransferResult {
        tracing::warn!(error = ?error, "download_file::error");
        on_error(error)
    }
}

pub struct DeleteOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    client: C,
    request_id: u64,
    inflight: Arc<InflightTransfers>,
    retry: NetworkRetry,
}

impl<C> DeleteOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    pub fn new(
        client: C,
        request_id: u64,
        inflight: Arc<InflightTransfers>,
        retry: NetworkRetry,
    ) -> Self {
        Self {
            client,
            request_id,
            inflight,
            retry,
        }
    }

    #[async_recursion]
    pub async fn run(&self, file: ExternalFile) -> Result<TransferResult> {
        let result = match self.client.delete_file(&file).await {
            Ok(status) => self.on_response(status),
            Err(e) => self.on_error(e),
        };

        if let TransferResult::Retry = result {
            let retries = self.retry.increment().await;

            tracing::debug!(retries = %retries, "delete_file::retry");
            self.notify_retry(retries - 1, self.retry.maximum_retries)
                .await;

            if self.retry.is_exhausted(retries) {
                tracing::debug!(
                  maximum_retries = %self.retry.maximum_retries,
                  "delete_file::retries_exhausted");
                return Ok(TransferResult::Fatal(
                    TransferError::RetryExhausted,
                ));
            }

            self.retry
                .wait_and_retry(retries, async move { self.run(file).await })
                .await?
        } else {
            Ok(result)
        }
    }
}

impl<C> TransferTask for DeleteOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    fn request_id(&self) -> u64 {
        self.request_id
    }

    fn inflight(&self) -> &InflightTransfers {
        &*self.inflight
    }

    fn on_response(&self, status: StatusCode) -> TransferResult {
        if status == StatusCode::OK || status == StatusCode::NOT_FOUND {
            TransferResult::Done
        } else {
            TransferResult::Retry
        }
    }

    fn on_error(&self, error: Error) -> TransferResult {
        tracing::warn!(error = ?error, "delete_file::error");
        on_error(error)
    }
}

pub struct MoveOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    client: C,
    request_id: u64,
    inflight: Arc<InflightTransfers>,
    retry: NetworkRetry,
}

impl<C> MoveOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    pub fn new(
        client: C,
        request_id: u64,
        inflight: Arc<InflightTransfers>,
        retry: NetworkRetry,
    ) -> Self {
        Self {
            client,
            request_id,
            inflight,
            retry,
        }
    }

    #[async_recursion]
    pub async fn run(
        &self,
        file: ExternalFile,
        dest: &ExternalFile,
    ) -> Result<TransferResult> {
        let result = match self.client.move_file(&file, dest).await {
            Ok(status) => self.on_response(status),
            Err(e) => self.on_error(e),
        };

        if let TransferResult::Retry = result {
            let retries = self.retry.increment().await;

            tracing::debug!(retries = %retries, "move_file::retry");
            self.notify_retry(retries - 1, self.retry.maximum_retries)
                .await;

            if self.retry.is_exhausted(retries) {
                tracing::debug!(
                  maximum_retries = %self.retry.maximum_retries,
                  "move_file::retries_exhausted");
                return Ok(TransferResult::Fatal(
                    TransferError::RetryExhausted,
                ));
            }

            self.retry
                .wait_and_retry(
                    retries,
                    async move { self.run(file, dest).await },
                )
                .await?
        } else {
            Ok(result)
        }
    }
}

impl<C> TransferTask for MoveOperation<C>
where
    C: SyncClient + Clone + Send + Sync + 'static,
{
    fn request_id(&self) -> u64 {
        self.request_id
    }

    fn inflight(&self) -> &InflightTransfers {
        &*self.inflight
    }

    fn on_response(&self, status: StatusCode) -> TransferResult {
        if status == StatusCode::OK {
            TransferResult::Done
        } else {
            TransferResult::Retry
        }
    }

    fn on_error(&self, error: Error) -> TransferResult {
        tracing::warn!(error = ?error, "move_file::error");
        on_error(error)
    }
}

trait TransferTask {
    fn on_response(&self, status: StatusCode) -> TransferResult;
    fn on_error(&self, error: Error) -> TransferResult;
    fn inflight(&self) -> &InflightTransfers;
    fn request_id(&self) -> u64;

    async fn notify_retry(&self, retry: u32, maximum: u32) {
        let notify = InflightNotification::TransferRetry {
            request_id: self.request_id(),
            retry,
            maximum,
        };
        notify_listeners(notify, &self.inflight().notifications).await;
    }
}

fn on_error(error: Error) -> TransferResult {
    match error {
        Error::Io(io) => match io.kind() {
            ErrorKind::NotFound => {
                TransferResult::Fatal(TransferError::TransferFileMissing)
            }
            _ => TransferResult::Retry,
        },
        _ => TransferResult::Retry,
    }
}