//! File transfer operations.
//!
//! Tasks that handle retry until exhaustion for
//! download, upload, move and delete operations.
use crate::{
    net::NetworkRetry,
    protocol::{
        transfer::{CancelReason, FileSyncClient},
        SyncClient,
    },
    sdk::{storage::files::ExternalFile, vfs, Paths},
    Error, Result,
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
    C: SyncClient<Error = Error>
        + FileSyncClient<Error = Error>
        + Clone
        + Send
        + Sync
        + 'static,
{
    client: C,
    paths: Arc<Paths>,
    transfer_id: u64,
    request_id: u64,
    inflight: Arc<InflightTransfers>,
    retry: NetworkRetry,
    cancel_retry: watch::Sender<CancelReason>,
}

impl<C> UploadOperation<C>
where
    C: SyncClient<Error = Error>
        + FileSyncClient<Error = Error>
        + Clone
        + Send
        + Sync
        + 'static,
{
    pub fn new(
        client: C,
        paths: Arc<Paths>,
        transfer_id: u64,
        request_id: u64,
        inflight: Arc<InflightTransfers>,
        retry: NetworkRetry,
        cancel_retry: watch::Sender<CancelReason>,
    ) -> Self {
        Self {
            client,
            paths,
            transfer_id,
            request_id,
            inflight,
            retry,
            cancel_retry,
        }
    }

    #[async_recursion]
    pub async fn run(
        &self,
        file: &ExternalFile,
        progress_tx: ProgressChannel,
        cancel_rx: watch::Receiver<CancelReason>,
    ) -> Result<TransferResult> {
        let path = self.paths.file_location(
            file.vault_id(),
            file.secret_id(),
            file.file_name().to_string(),
        );

        let result = match self
            .client
            .upload_file(file, &path, progress_tx.clone(), cancel_rx.clone())
            .await
        {
            Ok(status) => self.on_response(status),
            Err(e) => self.on_error(e),
        };

        if let TransferResult::Retry = result {
            let retries = self.retry.increment();

            tracing::debug!(retries = %retries, "upload_file::retry");
            self.notify_retry(
                self.transfer_id,
                retries,
                self.retry.maximum_retries,
            )
            .await;

            if self.retry.is_exhausted(retries) {
                tracing::debug!(
                  maximum_retries = %self.retry.maximum_retries,
                  "upload_file::retries_exhausted");
                return Ok(TransferResult::Fatal(
                    TransferError::RetryExhausted,
                ));
            }

            match self.retry
                .wait_and_retry(self.request_id, retries, async move {
                    self.run(file, progress_tx, cancel_rx).await
                }, self.cancel_retry.subscribe())
                .await {
                Ok(res) => res,
                Err(e) => {
                    match e {
                        Error::RetryCanceled(user_canceled) => {
                            Ok(TransferResult::Fatal(TransferError::Canceled(user_canceled)))
                        }
                        _ => Err(e),
                    }
                }
            }
        } else {
            Ok(result)
        }
    }
}

impl<C> TransferTask for UploadOperation<C>
where
    C: SyncClient<Error = Error>
        + FileSyncClient<Error = Error>
        + Clone
        + Send
        + Sync
        + 'static,
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
    C: SyncClient<Error = Error>
        + FileSyncClient<Error = Error>
        + Clone
        + Send
        + Sync
        + 'static,
{
    client: C,
    paths: Arc<Paths>,
    transfer_id: u64,
    request_id: u64,
    inflight: Arc<InflightTransfers>,
    retry: NetworkRetry,
    cancel_retry: watch::Sender<CancelReason>,
}

impl<C> DownloadOperation<C>
where
    C: SyncClient<Error = Error>
        + FileSyncClient<Error = Error>
        + Clone
        + Send
        + Sync
        + 'static,
{
    pub fn new(
        client: C,
        paths: Arc<Paths>,
        transfer_id: u64,
        request_id: u64,
        inflight: Arc<InflightTransfers>,
        retry: NetworkRetry,
        cancel_retry: watch::Sender<CancelReason>,
    ) -> Self {
        Self {
            client,
            paths,
            transfer_id,
            request_id,
            inflight,
            retry,
            cancel_retry,
        }
    }

    #[async_recursion]
    pub async fn run(
        &self,
        file: &ExternalFile,
        progress_tx: ProgressChannel,
        cancel_rx: watch::Receiver<CancelReason>,
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
                file,
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
            let retries = self.retry.increment();

            tracing::debug!(retries = %retries, "download_file::retry");
            self.notify_retry(
                self.transfer_id,
                retries,
                self.retry.maximum_retries,
            )
            .await;

            if self.retry.is_exhausted(retries) {
                tracing::debug!(
                  maximum_retries = %self.retry.maximum_retries,
                  "download_file::retries_exhausted");
                return Ok(TransferResult::Fatal(
                    TransferError::RetryExhausted,
                ));
            }

            match self.retry
                .wait_and_retry(self.request_id, retries, async move {
                    self.run(file, progress_tx, cancel_rx).await
                }, self.cancel_retry.subscribe())
                .await {
                Ok(res) => res,
                Err(e) => {
                    match e {
                        Error::RetryCanceled(user_canceled) => {
                            Ok(TransferResult::Fatal(TransferError::Canceled(user_canceled)))
                        }
                        _ => Err(e),
                    }
                }
            }
        } else {
            Ok(result)
        }
    }
}

impl<C> TransferTask for DownloadOperation<C>
where
    C: SyncClient<Error = Error>
        + FileSyncClient<Error = Error>
        + Clone
        + Send
        + Sync
        + 'static,
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
    transfer_id: u64,
    request_id: u64,
    inflight: Arc<InflightTransfers>,
    retry: NetworkRetry,
    cancel_retry: watch::Sender<CancelReason>,
}

impl<C> DeleteOperation<C>
where
    C: SyncClient<Error = Error>
        + FileSyncClient<Error = Error>
        + Clone
        + Send
        + Sync
        + 'static,
{
    pub fn new(
        client: C,
        transfer_id: u64,
        request_id: u64,
        inflight: Arc<InflightTransfers>,
        retry: NetworkRetry,
        cancel_retry: watch::Sender<CancelReason>,
    ) -> Self {
        Self {
            client,
            transfer_id,
            request_id,
            inflight,
            retry,
            cancel_retry,
        }
    }

    #[async_recursion]
    pub async fn run(&self, file: &ExternalFile) -> Result<TransferResult> {
        let result = match self.client.delete_file(file).await {
            Ok(status) => self.on_response(status),
            Err(e) => self.on_error(e),
        };

        if let TransferResult::Retry = result {
            let retries = self.retry.increment();

            tracing::debug!(retries = %retries, "delete_file::retry");
            self.notify_retry(
                self.transfer_id,
                retries,
                self.retry.maximum_retries,
            )
            .await;

            if self.retry.is_exhausted(retries) {
                tracing::debug!(
                  maximum_retries = %self.retry.maximum_retries,
                  "delete_file::retries_exhausted");
                return Ok(TransferResult::Fatal(
                    TransferError::RetryExhausted,
                ));
            }

            match self
                .retry
                .wait_and_retry(
                    self.request_id,
                    retries,
                    async move { self.run(file).await },
                    self.cancel_retry.subscribe(),
                )
                .await
            {
                Ok(res) => res,
                Err(e) => match e {
                    Error::RetryCanceled(user_canceled) => {
                        Ok(TransferResult::Fatal(TransferError::Canceled(
                            user_canceled,
                        )))
                    }
                    _ => Err(e),
                },
            }
        } else {
            Ok(result)
        }
    }
}

impl<C> TransferTask for DeleteOperation<C>
where
    C: SyncClient<Error = Error>
        + FileSyncClient<Error = Error>
        + Clone
        + Send
        + Sync
        + 'static,
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
    C: SyncClient<Error = Error>
        + FileSyncClient<Error = Error>
        + Clone
        + Send
        + Sync
        + 'static,
{
    client: C,
    transfer_id: u64,
    request_id: u64,
    inflight: Arc<InflightTransfers>,
    retry: NetworkRetry,
    cancel_retry: watch::Sender<CancelReason>,
}

impl<C> MoveOperation<C>
where
    C: SyncClient<Error = Error>
        + FileSyncClient<Error = Error>
        + Clone
        + Send
        + Sync
        + 'static,
{
    pub fn new(
        client: C,
        transfer_id: u64,
        request_id: u64,
        inflight: Arc<InflightTransfers>,
        retry: NetworkRetry,
        cancel_retry: watch::Sender<CancelReason>,
    ) -> Self {
        Self {
            client,
            transfer_id,
            request_id,
            inflight,
            retry,
            cancel_retry,
        }
    }

    #[async_recursion]
    pub async fn run(
        &self,
        file: &ExternalFile,
        dest: &ExternalFile,
    ) -> Result<TransferResult> {
        let result = match self.client.move_file(file, dest).await {
            Ok(status) => self.on_response(status),
            Err(e) => self.on_error(e),
        };

        if let TransferResult::Retry = result {
            let retries = self.retry.increment();

            tracing::debug!(retries = %retries, "move_file::retry");
            self.notify_retry(
                self.transfer_id,
                retries,
                self.retry.maximum_retries,
            )
            .await;

            if self.retry.is_exhausted(retries) {
                tracing::debug!(
                  maximum_retries = %self.retry.maximum_retries,
                  "move_file::retries_exhausted");
                return Ok(TransferResult::Fatal(
                    TransferError::RetryExhausted,
                ));
            }

            match self
                .retry
                .wait_and_retry(
                    self.request_id,
                    retries,
                    async move { self.run(file, dest).await },
                    self.cancel_retry.subscribe(),
                )
                .await
            {
                Ok(res) => res,
                Err(e) => match e {
                    Error::RetryCanceled(user_canceled) => {
                        Ok(TransferResult::Fatal(TransferError::Canceled(
                            user_canceled,
                        )))
                    }
                    _ => Err(e),
                },
            }
        } else {
            Ok(result)
        }
    }
}

impl<C> TransferTask for MoveOperation<C>
where
    C: SyncClient<Error = Error>
        + FileSyncClient<Error = Error>
        + Clone
        + Send
        + Sync
        + 'static,
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
        match error {
            Error::ResponseJson(StatusCode::NOT_FOUND, _) => {
                TransferResult::Fatal(TransferError::MovedMissing)
            }
            _ => on_error(error),
        }
    }
}

trait TransferTask {
    fn on_response(&self, status: StatusCode) -> TransferResult;
    fn on_error(&self, error: Error) -> TransferResult;
    fn inflight(&self) -> &InflightTransfers;
    fn request_id(&self) -> u64;

    async fn notify_retry(&self, transfer_id: u64, retry: u32, maximum: u32) {
        let notify = InflightNotification::TransferRetry {
            transfer_id,
            request_id: self.request_id(),
            retry,
            maximum,
        };
        notify_listeners(notify, &self.inflight().notifications).await;
    }
}

fn on_error(error: Error) -> TransferResult {
    if let Some(reason) = error.cancellation_reason() {
        return TransferResult::Fatal(TransferError::Canceled(
            reason.clone(),
        ));
    }

    match error {
        Error::Io(io) => match io.kind() {
            ErrorKind::NotFound => {
                TransferResult::Fatal(TransferError::FileMissing)
            }
            _ => TransferResult::Retry,
        },
        _ => TransferResult::Retry,
    }
}
