//! Tracks inflight file transfer requests.
use crate::sdk::{
    storage::files::{ExternalFile, TransferOperation},
    sync::Origin,
};

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tokio::sync::{broadcast, RwLock};

use super::{CancelChannel, TransferError};

/// Notification for inflight transfers.
#[derive(Debug, Clone)]
pub enum InflightNotification {
    /// Notify a transfer was added.
    TransferAdded {
        /// Transfer identifier.
        transfer_id: u64,
        /// Request identifier.
        request_id: u64,
        /// Server origin.
        origin: Origin,
        /// File information.
        file: ExternalFile,
        /// Transfer operation.
        operation: TransferOperation,
    },
    /// Notify a transfer was updated with progress information.
    ///
    /// This notification is only sent for uploads and downloads.
    TransferUpdate {
        /// Transfer identifier.
        transfer_id: u64,
        /// Request identifier.
        request_id: u64,
        /// Bytes transferred.
        bytes_transferred: u64,
        /// Bytes total.
        bytes_total: Option<u64>,
    },
    /// Notify a transfer is being retried.
    TransferRetry {
        /// Transfer identifier.
        transfer_id: u64,
        /// Request identifier.
        request_id: u64,
        /// Retry number.
        retry: u32,
        /// Maximum number of retries.
        maximum: u32,
    },
    /// Notify a transfer is stopped due to an error.
    TransferError {
        /// Transfer identifier.
        transfer_id: u64,
        /// Request identifier.
        request_id: u64,
        /// Error reason.
        reason: TransferError,
    },
    /// Notify a transfer was completed.
    TransferDone {
        /// Transfer identifier.
        transfer_id: u64,
        /// Request identifier.
        request_id: u64,
    },
}

/// Inflight file transfer.
#[derive(Debug)]
pub struct InflightRequest {
    /// Server origin.
    pub origin: Origin,
    /// External file information.
    pub file: ExternalFile,
    /// Transfer operation.
    pub operation: TransferOperation,
    /// Cancel channel for uploads and downloads.
    pub cancel: CancelChannel,
}

impl InflightRequest {
    /// Cancel the inflight request.
    pub async fn cancel(self, user_canceled: bool) -> bool {
        self.cancel.send(user_canceled).is_ok()
    }
}

/// Collection of pending transfers.
pub struct InflightTransfers {
    inflight: Arc<RwLock<HashMap<u64, InflightRequest>>>,
    request_id: AtomicU64,
    pub(super) notifications: broadcast::Sender<InflightNotification>,
}

impl InflightTransfers {
    /// Create new pending transfers.
    pub(crate) fn new() -> Self {
        let (notifications, _) = broadcast::channel(2048);
        Self {
            inflight: Arc::new(RwLock::new(Default::default())),
            request_id: AtomicU64::new(1),
            notifications,
        }
    }

    /// Cancel all inflight transfers.
    pub async fn cancel_all(&self, user_canceled: bool) {
        let mut writer = self.inflight.write().await;
        for (id, request) in writer.drain() {
            tracing::info!(
                request_id = %id,
                op = ?request.operation,
                "inflight::cancel",
            );
            request.cancel(user_canceled).await;
        }
    }

    /// Cancel a single inflight transfer.
    pub async fn cancel_one(
        &self,
        request_id: &u64,
        user_canceled: bool,
    ) -> bool {
        let mut writer = self.inflight.write().await;
        if let Some(req) = writer.remove(request_id) {
            req.cancel(user_canceled).await
        } else {
            false
        }
    }

    /// Inflight notifications channel.
    pub fn notifications(&self) -> &broadcast::Sender<InflightNotification> {
        &self.notifications
    }

    /// Determine if the inflight transfers is empty.
    pub async fn is_empty(&self) -> bool {
        let queue = self.inflight.read().await;
        queue.is_empty()
    }

    /// Next request id.
    pub(super) fn request_id(&self) -> u64 {
        self.request_id.fetch_add(1, Ordering::SeqCst)
    }

    pub(super) async fn insert_transfer(
        &self,
        request_id: u64,
        request: InflightRequest,
    ) {
        let mut inflight = self.inflight.write().await;
        inflight.insert(request_id, request);
    }

    pub(super) async fn remove_transfer(&self, request_id: &u64) {
        let mut inflight = self.inflight.write().await;
        inflight.remove(request_id);
    }
}
