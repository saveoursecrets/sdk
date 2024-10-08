#![allow(clippy::result_large_err)]
#![allow(clippy::module_inception)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Networking support for the [sos-sdk crate](https://docs.rs/sos-sdk/latest/sos_sdk/).
//!
//! If the `listen` feature is enabled the client is compiled
//! with support for sending and listening for change notification over
//! a websocket connection.

mod account;
mod error;
#[cfg(feature = "hashcheck")]
pub mod hashcheck;
mod net;
#[cfg(feature = "pairing")]
pub mod pairing;
mod sync;

pub use reqwest;
pub use sos_sdk as sdk;
// FIXME: remove this
pub use sos_protocol as protocol;

pub use account::*;
pub use error::Error;
#[cfg(feature = "listen")]
pub use net::{changes, connect, ListenOptions, WebSocketHandle};
pub use net::{HttpClient, NetworkRetry};
pub use sync::{
    AccountSync, RemoteResult, RemoteSync, SyncClient, SyncResult,
};

#[cfg(any(
    feature = "preferences",
    feature = "security-report",
    feature = "system-messages"
))]
pub use sos_account_extras as extras;

/// Result type for the client module.
pub type Result<T> = std::result::Result<T, error::Error>;

/// Determine if the offline environment variable is set.
pub fn is_offline() -> bool {
    use crate::sdk::constants::SOS_OFFLINE;
    std::env::var(SOS_OFFLINE).ok().is_some()
}

#[cfg(any(feature = "listen", feature = "pairing"))]
mod websocket_request {
    use super::Result;
    use sos_sdk::url::Url;
    use tokio_tungstenite::tungstenite::{
        self, client::IntoClientRequest, handshake::client::generate_key,
    };

    pub(crate) struct WebSocketRequest {
        pub(crate) uri: Url,
        host: String,
        bearer: Option<String>,
        origin: url::Origin,
    }

    impl WebSocketRequest {
        /// Create a new websocket request.
        pub fn new(url: &Url, path: &str) -> Result<Self> {
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
                .header("upgrade", "websocket");
            Ok(request.body(())?)
        }
    }
}

#[cfg(any(feature = "listen", feature = "pairing"))]
pub(crate) use websocket_request::WebSocketRequest;
