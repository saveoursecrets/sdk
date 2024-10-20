//! HTTP transport trait and implementations.
use super::{Error, Result};
use crate::CancelReason;
use sos_sdk::{
    encode,
    signer::{
        ecdsa::{BinaryEcdsaSignature, Signature},
        ed25519::{BinaryEd25519Signature, Signature as Ed25519Signature},
    },
};

use std::{
    future::Future,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{sync::watch, time::sleep};

mod http;
#[cfg(feature = "listen")]
mod websocket;

pub use self::http::HttpClient;

#[cfg(feature = "listen")]
pub use websocket::{changes, connect, ListenOptions, WebSocketHandle};

/// Network retry state and logic for exponential backoff.
#[derive(Debug, Clone)]
pub struct NetworkRetry {
    retries: Arc<AtomicU32>,
    pub(crate) reconnect_interval: u16,
    pub(crate) maximum_retries: u32,
}

impl Default for NetworkRetry {
    fn default() -> Self {
        Self::new(4, 1000)
    }
}

impl NetworkRetry {
    /// Create a new network retry.
    ///
    /// The reconnect interval is a *base interval* in milliseconds
    /// for the exponential backoff so use a small value such as
    /// `1000` or `2000`.
    pub fn new(maximum_retries: u32, reconnect_interval: u16) -> Self {
        Self {
            retries: Arc::new(AtomicU32::from(1)),
            reconnect_interval,
            maximum_retries,
        }
    }

    /// Millisecond delay for a current retry.
    pub fn delay(&self, retries: u32) -> u64 {
        (retries * self.reconnect_interval as u32) as u64
    }

    /// Clone of this network retry with the retry counter reset.
    pub fn reset(&self) -> Self {
        Self {
            retries: Arc::new(AtomicU32::from(1)),
            reconnect_interval: self.reconnect_interval,
            maximum_retries: self.maximum_retries,
        }
    }

    /// Increment for next retry attempt.
    pub fn increment(&self) -> u32 {
        self.retries.fetch_add(1, Ordering::SeqCst)
    }

    /// Determine if retry attempts are exhausted.
    pub fn is_exhausted(&self, retries: u32) -> bool {
        retries > self.maximum_retries
    }

    /// Wait and then retry.
    pub async fn wait_and_retry<D, T, F>(
        &self,
        id: D,
        retries: u32,
        callback: F,
        mut cancel: watch::Receiver<CancelReason>,
    ) -> Result<T>
    where
        D: std::fmt::Display,
        F: Future<Output = T>,
    {
        let factor = 2u64.checked_pow(retries).ok_or(Error::RetryOverflow)?;
        let delay = self.reconnect_interval as u64 * factor;
        tracing::debug!(
            id = %id,
            delay = %delay,
            retries = %retries,
            maximum_retries = %self.maximum_retries,
            "retry",
        );
        loop {
            tokio::select! {
                _ = cancel.changed() => {
                    let reason = cancel.borrow();
                    tracing::debug!(id = %id, "retry::canceled");
                    return Err(Error::RetryCanceled(reason.clone()));
                }
                _ = sleep(Duration::from_millis(delay)) => {
                    return Ok(callback.await)
                }
            };
        }
    }
}

pub(crate) async fn encode_account_signature(
    signature: Signature,
) -> Result<String> {
    let signature: BinaryEcdsaSignature = signature.into();
    Ok(bs58::encode(encode(&signature).await?).into_string())
}

pub(crate) async fn encode_device_signature(
    signature: Ed25519Signature,
) -> Result<String> {
    let signature: BinaryEd25519Signature = signature.into();
    Ok(bs58::encode(encode(&signature).await?).into_string())
}

pub(crate) fn bearer_prefix(
    account_signature: &str,
    device_signature: Option<&str>,
) -> String {
    if let Some(device_signature) = device_signature {
        format!("Bearer {}.{}", account_signature, device_signature)
    } else {
        format!("Bearer {}", account_signature)
    }
}
