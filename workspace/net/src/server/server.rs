use super::{
    config::TlsConfig,
    handlers::{
        account::AccountHandler,
        api, connections,
        files::{file_operation_lock, FileHandler},
        home,
        service::ServiceHandler,
    },
    Backend, Result, ServerConfig,
};
use crate::sdk::storage::files::ExternalFile;
use axum::{
    extract::Extension,
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        HeaderValue, Method,
    },
    middleware,
    routing::{get, post, put},
    Router,
};
use axum_server::{tls_rustls::RustlsConfig, Handle};
use serde::{Deserialize, Serialize};

use sos_sdk::signer::ecdsa::Address;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};
use tokio::sync::{RwLock, RwLockReadGuard};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

#[cfg(feature = "listen")]
use super::handlers::websocket::{upgrade, WebSocketConnection};

/// Server state.
pub struct State {
    /// The server configuration.
    pub config: ServerConfig,
    /// Server information.
    pub info: ServerInfo,
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
        let tls = reader.config.tls.as_ref().cloned();
        drop(reader);

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
        let tls = RustlsConfig::from_pem_file(&tls.cert, &tls.key).await?;
        let app = Server::router(Arc::clone(&state), backend, origins)?;

        self.startup_message(state, &addr, true).await;

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
        let app = Server::router(Arc::clone(&state), backend, origins)?;

        self.startup_message(state, &addr, false).await;

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
        tls: bool,
    ) {
        tracing::info!(addr = %addr);
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
            .route("/api/account", post(ServiceHandler::account))
            .route(
                "/api/v1/sync/account",
                post(AccountHandler::create_account)
                    .get(AccountHandler::fetch_account),
            )
            .route(
                "/api/v1/sync/account/status",
                get(AccountHandler::sync_status),
            )
            .route(
                "/api/v1/sync/file/:vault_id/:secret_id/:file_name",
                put(FileHandler::receive_file)
                    .post(FileHandler::move_file)
                    .get(FileHandler::send_file)
                    .delete(FileHandler::delete_file)
                    .route_layer(middleware::from_fn(file_operation_lock)),
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
