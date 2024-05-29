//! Tracks inflight file transfer requests and sends
//! notifications so that applications can monitor the
//! progress of file transfers.
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
use tokio::sync::{broadcast, Mutex, RwLock};

use super::{notify_listeners, CancelChannel, TransferError};

/// Notification for inflight transfers.
#[derive(Debug, Clone)]
pub enum InflightNotification {
    /// Notify a transfer was added.
    TransferAdded {
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
        /// Request identifier.
        request_id: u64,
        /// Bytes transferred.
        bytes_transferred: u64,
        /// Bytes total.
        bytes_total: Option<u64>,
    },
    /// Notify a transfer was removed from inflight collection.
    TransferRemoved {
        /// Request identifier.
        request_id: u64,
    },
    /// Notify a transfer is being retried.
    TransferRetry {
        /// Request identifier.
        request_id: u64,
        /// Retry number.
        retry: u32,
        /// Maximum number of retries.
        maximum: u32,
    },
    /// Notify a transfer is stopped due to an error.
    TransferError {
        /// Request identifier.
        request_id: u64,
        /// Error reason.
        reason: TransferError,
    },
    /// Notify a transfer was completed.
    TransferDone {
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
    pub cancel: Option<CancelChannel>,
}

impl InflightRequest {
    /// Cancel the inflight request.
    pub async fn cancel(mut self) -> bool {
        if let Some(cancel) = self.cancel.take() {
            cancel.send(()).is_ok()
        } else {
            false
        }
    }
}

/// Collection of pending transfers.
pub struct InflightTransfers {
    inflight: Arc<RwLock<HashMap<u64, InflightRequest>>>,
    request_id: Arc<Mutex<AtomicU64>>,
    pub(super) notifications: broadcast::Sender<InflightNotification>,
}

impl InflightTransfers {
    /// Create new pending transfers.
    pub(crate) fn new() -> Self {
        let (notifications, _) = broadcast::channel(2048);
        Self {
            inflight: Arc::new(RwLock::new(Default::default())),
            request_id: Arc::new(Mutex::new(AtomicU64::new(1))),
            notifications,
        }
    }

    /// Cancel all inflight transfers.
    pub async fn cancel(&self) {
        let mut writer = self.inflight.write().await;
        for (id, request) in writer.drain() {
            tracing::info!(
                request_id = %id,
                op = ?request.operation,
                "inflight::cancel",
            );
            request.cancel().await;
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
    pub(super) async fn request_id(&self) -> u64 {
        let id = self.request_id.lock().await;
        id.fetch_add(1, Ordering::SeqCst)
    }

    pub(super) async fn insert_transfer(
        &self,
        request_id: u64,
        request: InflightRequest,
    ) {
        let notify = InflightNotification::TransferAdded {
            request_id,
            origin: request.origin.clone(),
            file: request.file.clone(),
            operation: request.operation.clone(),
        };

        let mut inflight = self.inflight.write().await;
        inflight.insert(request_id, request);

        notify_listeners(notify, &self.notifications).await;
    }

    pub(super) async fn remove_transfer(&self, request_id: &u64) {
        let notify = InflightNotification::TransferRemoved {
            request_id: *request_id,
        };

        let mut inflight = self.inflight.write().await;
        inflight.remove(request_id);

        notify_listeners(notify, &self.notifications).await;
    }
}
