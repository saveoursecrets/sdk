use super::{
    config::TlsConfig,
    handlers::{
        api, connections, files::FileHandler, home, service::ServiceHandler,
    },
    Backend, Result, ServerConfig, TransportManager,
};
use axum::{
    extract::Extension,
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        HeaderValue, Method,
    },
    routing::{get, post, put},
    Router,
};
use axum_server::{tls_rustls::RustlsConfig, Handle};
use futures::StreamExt;
use mpc_protocol::Keypair;
use serde::{Deserialize, Serialize};
use crate::sdk::storage::files::ExternalFile;

use std::time::Duration;
use std::{collections::{HashMap, HashSet}, net::SocketAddr, sync::Arc};
use tokio::sync::{RwLock, RwLockReadGuard};
use tokio_stream::wrappers::IntervalStream;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use web3_address::ethereum::Address;

#[cfg(feature = "listen")]
use super::handlers::websocket::{upgrade, WebSocketConnection};

async fn session_reaper(state: ServerState, interval_secs: u64) {
    let interval = tokio::time::interval(Duration::from_secs(interval_secs));
    let mut stream = IntervalStream::new(interval);
    while (stream.next().await).is_some() {
        let mut writer = state.write().await;
        let expired_transports = writer.transports.expired_keys();
        tracing::debug!(
            expired_transports = %expired_transports.len());
        for key in expired_transports {
            writer.transports.remove_channel(&key);
        }
    }
}

/// Server state.
pub struct State {
    /// Server keypair.
    pub keypair: Keypair,
    /// The server configuration.
    pub config: ServerConfig,
    /// Server information.
    pub info: ServerInfo,
    /// Server transport manager.
    pub transports: TransportManager,
    /// Map of websocket  channels by authenticated
    /// client address.
    pub sockets: HashMap<Address, WebSocketConnection>,
}

/// Server information.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    /// Name of the crate.
    pub name: String,
    /// Version of the crate.
    pub version: String,
    /// Noise protocol public key.
    #[serde(with = "hex::serde")]
    pub public_key: Vec<u8>,
}

/// State for the server.
pub type ServerState = Arc<RwLock<State>>;

/// State for the server backend.
pub type ServerBackend = Arc<RwLock<Backend>>;

/// Transfer operations in progress.
pub type TransferOperations = HashSet<ExternalFile>;

/// State for the file transfer operations.
pub type ServerTransfer = Arc<RwLock<TransferOperations>>;

/// Web server implementation.
#[derive(Default)]
pub struct Server;

impl Server {
    /// Create a new server.
    pub fn new() -> Self {
        Default::default()
    }

    /// Start the server.
    pub async fn start(
        &self,
        addr: SocketAddr,
        state: ServerState,
        backend: ServerBackend,
        handle: Handle,
    ) -> Result<()> {
        let reader = state.read().await;
        let origins = Server::read_origins(&reader)?;
        let reap_interval = reader.config.session.reap_interval;
        let tls = reader.config.tls.as_ref().cloned();
        drop(reader);

        // Spawn task to reap expired sessions
        tokio::task::spawn(session_reaper(Arc::clone(&state), reap_interval));

        if let Some(tls) = tls {
            self.run_tls(addr, state, backend, handle, origins, tls)
                .await
        } else {
            self.run(addr, state, backend, handle, origins).await
        }
    }

    /// Start the server running on HTTPS.
    async fn run_tls(
        &self,
        addr: SocketAddr,
        state: ServerState,
        backend: ServerBackend,
        handle: Handle,
        origins: Vec<HeaderValue>,
        tls: TlsConfig,
    ) -> Result<()> {
        let public_key = {
            let reader = state.read().await;
            reader.keypair.public_key().to_vec()
        };

        let tls = RustlsConfig::from_pem_file(&tls.cert, &tls.key).await?;
        let app = Server::router(Arc::clone(&state), backend, origins)?;

        self.startup_message(state, &addr, &public_key, true).await;

        axum_server::bind_rustls(addr, tls)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
        Ok(())
    }

    /// Start the server running on HTTP.
    async fn run(
        &self,
        addr: SocketAddr,
        state: ServerState,
        backend: ServerBackend,
        handle: Handle,
        origins: Vec<HeaderValue>,
    ) -> Result<()> {
        let public_key = {
            let reader = state.read().await;
            reader.keypair.public_key().to_vec()
        };

        let app = Server::router(Arc::clone(&state), backend, origins)?;

        self.startup_message(state, &addr, &public_key, false).await;

        axum_server::bind(addr)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
        Ok(())
    }

    async fn startup_message(
        &self,
        state: ServerState,
        addr: &SocketAddr,
        public_key: &[u8],
        tls: bool,
    ) {
        tracing::info!(addr = %addr);
        tracing::info!(public_key = %hex::encode(public_key));
        tracing::info!(tls = %tls);
        {
            let reader = state.read().await;
            if let Some(allow) = &reader.config.access.allow {
                for address in allow {
                    tracing::info!(allow = %address);
                }
            }
            if let Some(deny) = &reader.config.access.deny {
                for address in deny {
                    tracing::info!(deny = %address);
                }
            }
        }
    }

    fn read_origins(
        reader: &RwLockReadGuard<'_, State>,
    ) -> Result<Vec<HeaderValue>> {
        let mut origins = Vec::new();
        for url in reader.config.cors.origins.iter() {
            origins.push(HeaderValue::from_str(
                url.as_str().trim_end_matches('/'),
            )?);
        }
        Ok(origins)
    }

    fn router(
        state: ServerState,
        backend: ServerBackend,
        origins: Vec<HeaderValue>,
    ) -> Result<Router> {
        let cors = CorsLayer::new()
            .allow_methods(vec![Method::GET, Method::POST])
            .allow_credentials(true)
            .allow_headers(vec![AUTHORIZATION, CONTENT_TYPE])
            .expose_headers(vec![])
            .allow_origin(origins);

        let mut app = Router::new()
            .route("/", get(home))
            .route("/api", get(api))
            .route("/api/connections", get(connections))
            .route("/api/handshake", post(ServiceHandler::handshake))
            .route("/api/account", post(ServiceHandler::account))
            .route(
                "/api/file/:vault_id/:secret_id/:file_name",
                put(FileHandler::receive_file)
                    .post(FileHandler::move_file)
                    .get(FileHandler::send_file)
                    .delete(FileHandler::delete_file),
            )
            .route("/api/sync", post(ServiceHandler::sync));

        #[cfg(feature = "listen")]
        {
            app = app.route("/api/changes", get(upgrade));
        }

        let file_operations: ServerTransfer =
            Arc::new(RwLock::new(HashSet::new()));

        app = app
            .layer(cors)
            .layer(TraceLayer::new_for_http())
            .layer(Extension(backend))
            .layer(Extension(file_operations))
            .layer(Extension(state));

        Ok(app)
    }
}
