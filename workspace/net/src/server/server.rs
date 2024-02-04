use super::{
    config::TlsConfig,
    handlers::{
        account, api, connections,
        files::{self, file_operation_lock},
        home,
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
    response::{IntoResponse, Json},
    routing::{get, patch, post, put},
    Router,
};
use axum_server::{tls_rustls::RustlsConfig, Handle};
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

#[cfg(feature = "pairing")]
use super::handlers::relay::{upgrade as relay_upgrade, RelayState};

/// Server state.
pub struct State {
    /// The server configuration.
    pub config: ServerConfig,
    /// Map of websocket  channels by authenticated
    /// client address.
    pub sockets: HashMap<Address, WebSocketConnection>,
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
            .allow_methods(vec![
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
            ])
            .allow_credentials(true)
            .allow_headers(vec![AUTHORIZATION, CONTENT_TYPE])
            .expose_headers(vec![])
            .allow_origin(origins);

        let v1 = {
            let mut router = Router::new()
                .route("/", get(api))
                .route("/docs", get(apidocs))
                .route("/docs/", get(apidocs))
                .route("/docs/openapi.json", get(openapi))
                .route(
                    "/sync/account",
                    post(account::create_account)
                        .put(account::sync_account)
                        .get(account::fetch_account),
                )
                .route("/sync/account/status", get(account::sync_status))
                .route("/sync/files", post(files::compare_files))
                .route(
                    "/sync/file/:vault_id/:secret_id/:file_name",
                    put(files::receive_file)
                        .post(files::move_file)
                        .get(files::send_file)
                        .delete(files::delete_file)
                        .route_layer(middleware::from_fn(
                            file_operation_lock,
                        )),
                );

            #[cfg(feature = "device")]
            {
                router = router.route(
                    "/sync/account/devices",
                    patch(account::patch_devices),
                );
            }

            #[cfg(feature = "listen")]
            {
                router = router
                    .route("/sync/connections", get(connections))
                    .route("/sync/changes", get(upgrade));
            }

            #[cfg(feature = "pairing")]
            {
                router = router.route("/relay", get(relay_upgrade));
            }

            router
        };

        #[cfg(feature = "pairing")]
        let relay: RelayState = Arc::new(RwLock::new(HashMap::new()));

        let file_operations: ServerTransfer =
            Arc::new(RwLock::new(HashSet::new()));

        let mut v1 = v1.layer(cors).layer(TraceLayer::new_for_http());

        #[cfg(feature = "pairing")]
        {
            v1 = v1.layer(Extension(relay));
        }

        v1 = v1
            .layer(Extension(backend))
            .layer(Extension(file_operations))
            .layer(Extension(state));

        let app = Router::new()
            .route("/", get(home))
            .nest_service("/api/v1", v1);

        Ok(app)
    }
}

/// Get OpenAPI JSON definition.
#[utoipa::path(
    get,
    path = "/docs/openapi.json",
    responses(
        (
            status = StatusCode::OK,
            description = "OpenAPI definition",
        ),
    ),
)]
pub async fn openapi() -> impl IntoResponse {
    let value = crate::server::api_docs::openapi();
    Json(serde_json::json!(&value))
}

/// OpenAPI documentation.
#[utoipa::path(
    get,
    path = "/docs",
    responses(
        (
            status = StatusCode::OK,
            description = "Render OpenAPI documentation",
        ),
    ),
)]
pub async fn apidocs() -> impl IntoResponse {
    use utoipa_rapidoc::RapiDoc;
    let rapidoc = RapiDoc::new("/api/v1/docs/openapi.json");
    let html = rapidoc.to_html();
    ([(CONTENT_TYPE, "text/html")], html)
}
