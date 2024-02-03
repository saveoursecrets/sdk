//! Client user account and types for bridging with remote origins.

mod account;
#[cfg(feature = "device")]
pub mod enrollment;
mod error;
#[cfg(feature = "hashcheck")]
pub mod hashcheck;
mod net;
mod sync;

pub use account::*;
pub use error::Error;
pub use net::HttpClient;
#[cfg(feature = "listen")]
pub use net::{changes, connect, ListenOptions, WebSocketHandle};
#[cfg(all(feature = "device", feature = "pairing"))]
pub mod pairing;
pub use sync::{RemoteSync, SyncError, SyncOptions};

/// Result type for the client module.
pub type Result<T> = std::result::Result<T, error::Error>;

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
