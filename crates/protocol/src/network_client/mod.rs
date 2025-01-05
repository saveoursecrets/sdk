//! HTTP transport trait and implementations.
use super::{Error, Result};
use crate::transfer::CancelReason;
use sos_sdk::encode;
use sos_signer::{
    ecdsa::{BinaryEcdsaSignature, Signature},
    ed25519::{BinaryEd25519Signature, Signature as Ed25519Signature},
};
use std::{
    future::Future,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::watch;

mod http;
#[cfg(feature = "listen")]
mod websocket;

pub use self::http::HttpClient;

#[cfg(feature = "listen")]
pub use websocket::{changes, connect, ListenOptions, WebSocketHandle};

/// Network retry state and logic for exponential backoff.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone)]
pub struct NetworkRetry {
    retries: Arc<AtomicU32>,
    /// Reconnect interval.
    pub reconnect_interval: u16,
    /// Maximum number of retries.
    pub maximum_retries: u32,
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for NetworkRetry {
    fn default() -> Self {
        Self::new(4, 1000)
    }
}

#[cfg(not(target_arch = "wasm32"))]
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

    /// Exponential backoff millisecond delay for a retry counter.
    pub fn delay(&self, retries: u32) -> Result<u64> {
        let factor = 2u64.checked_pow(retries).ok_or(Error::RetryOverflow)?;
        Ok(self.reconnect_interval as u64 * factor)
    }

    /// Current number of retries.
    pub fn retries(&self) -> u32 {
        self.retries.load(Ordering::SeqCst)
    }

    /// Maximum number of retries.
    pub fn maximum(&self) -> u32 {
        self.maximum_retries
    }

    /// Reset retries counter.
    pub fn reset(&self) {
        self.retries.store(1, Ordering::SeqCst)
    }

    /// Clone of this network retry with the retry counter reset.
    pub fn clone_reset(&self) -> Self {
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
        let delay = self.delay(retries)?;
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
                _ = tokio::time::sleep(Duration::from_millis(delay)) => {
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
    device_signature: &str,
) -> String {
    format!("Bearer {}.{}", account_signature, device_signature)

    /*
    if let Some(device_signature) = device_signature {
        format!("Bearer {}.{}", account_signature, device_signature)
    } else {
        format!("Bearer {}", account_signature)
    }
    */
}

#[cfg(any(feature = "listen", feature = "pairing"))]
mod websocket_request {
    use crate::constants::X_SOS_ACCOUNT_ID;

    use super::Result;
    use sos_core::AccountId;
    use tokio_tungstenite::tungstenite::{
        self, client::IntoClientRequest, handshake::client::generate_key,
    };
    use url::Url;

    /// Build a websocket connection request.
    pub struct WebSocketRequest {
        /// Account identifier.
        pub account_id: AccountId,
        /// Remote URI.
        pub uri: Url,
        /// Remote host.
        pub host: String,
        /// Bearer authentication.
        pub bearer: Option<String>,
        /// URL origin.
        pub origin: url::Origin,
    }

    impl WebSocketRequest {
        /// Create a new websocket request.
        pub fn new(
            account_id: AccountId,
            url: &Url,
            path: &str,
        ) -> Result<Self> {
            let origin = url.origin();
            let host = url.host_str().unwrap().to_string();

            let mut uri = url.join(path)?;
            let scheme = if uri.scheme() == "http" {
                "ws"
            } else if uri.scheme() == "https" {
                "wss"
            } else {
                panic!("bad url scheme for websocket, requires http(s)");
            };

            uri.set_scheme(scheme)
                .expect("failed to set websocket scheme");

            Ok(Self {
                account_id,
                host,
                uri,
                origin,
                bearer: None,
            })
        }

        /// Set bearer authorization.
        pub fn set_bearer(&mut self, bearer: String) {
            self.bearer = Some(bearer);
        }
    }

    impl IntoClientRequest for WebSocketRequest {
        fn into_client_request(
            self,
        ) -> std::result::Result<http::Request<()>, tungstenite::Error>
        {
            let origin = self.origin.unicode_serialization();
            let mut request =
                http::Request::builder().uri(self.uri.to_string());
            if let Some(bearer) = self.bearer {
                request = request.header("authorization", bearer);
            }
            request = request
                .header("sec-websocket-key", generate_key())
                .header("sec-websocket-version", "13")
                .header("host", self.host)
                .header("origin", origin)
                .header("connection", "keep-alive, Upgrade")
                .header(X_SOS_ACCOUNT_ID, self.account_id.to_string())
                .header("upgrade", "websocket");
            Ok(request.body(())?)
        }
    }
}

#[cfg(any(feature = "listen", feature = "pairing"))]
pub use websocket_request::WebSocketRequest;
