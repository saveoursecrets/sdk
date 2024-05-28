//! HTTP transport trait and implementations.
use sos_sdk::{
    encode,
    signer::{
        ecdsa::{BinaryEcdsaSignature, Signature},
        ed25519::{BinaryEd25519Signature, Signature as Ed25519Signature},
    },
};

use super::{Error, Result};

use std::{
    future::Future,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{sync::Mutex, time::sleep};

mod http;
#[cfg(feature = "listen")]
mod websocket;

pub use self::http::HttpClient;

#[cfg(feature = "listen")]
pub use websocket::{changes, connect, ListenOptions, WebSocketHandle};

/// Network retry state and logic for exponential backoff.
#[derive(Debug, Clone)]
pub struct NetworkRetry {
    retries: Arc<Mutex<AtomicU64>>,
    pub(crate) reconnect_interval: u64,
    pub(crate) maximum_retries: u64,
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
    pub fn new(maximum_retries: u64, reconnect_interval: u64) -> Self {
        Self {
            retries: Arc::new(Mutex::new(AtomicU64::from(1))),
            reconnect_interval,
            maximum_retries,
        }
    }

    /// Increment for next retry attempt.
    pub async fn increment(&self) -> u64 {
        let retries = self.retries.lock().await;
        retries.fetch_add(1, Ordering::SeqCst)
    }

    /// Determine if retry attempts are exhausted.
    pub fn is_exhausted(&self, retries: u64) -> bool {
        retries > self.maximum_retries
    }

    /// Wait and then retry.
    pub async fn wait_and_retry<T, F>(
        &self,
        retries: u64,
        callback: F,
    ) -> Result<T>
    where
        F: Future<Output = T>,
    {
        let factor = 2u64
            .checked_pow(retries as u32)
            .ok_or(Error::RetryOverflow)?;
        let delay = self.reconnect_interval * factor;
        tracing::debug!(
            delay = %delay,
            retries = %retries,
            maximum_retries = %self.maximum_retries,
            "retry",
        );
        sleep(Duration::from_millis(delay)).await;
        Ok(callback.await)
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
