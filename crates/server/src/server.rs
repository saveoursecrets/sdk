use crate::{
    config::{self, TlsConfig},
    handlers::{account, api, home, websocket::WebSocketAccount},
    Backend, Result, ServerConfig, SslConfig, StorageConfig,
};
use axum::{
    extract::Extension,
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        HeaderValue, Method,
    },
    middleware,
    response::{IntoResponse, Json},
    routing::{get, post, put},
    Router,
};
use axum_server::{tls_rustls::RustlsConfig, Handle};
use colored::Colorize;
use futures::StreamExt;
use sos_core::{AccountId, UtcDateTime};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};
use tokio::sync::{Mutex, RwLock, RwLockReadGuard};
use tower_http::{
    cors::CorsLayer,
    trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use tracing::Level;

#[cfg(feature = "acme")]
use tokio_rustls_acme::{caches::DirCache, AcmeConfig};

#[cfg(feature = "listen")]
use super::handlers::websocket::upgrade;

use sos_core::ExternalFile;

#[cfg(feature = "pairing")]
use super::handlers::relay::{upgrade as relay_upgrade, RelayState};

/// Server state.
pub struct State {
    /// The server configuration.
    pub config: ServerConfig,
    /// Map of websocket channels by account identifier.
    pub(crate) sockets: HashMap<AccountId, WebSocketAccount>,
}

impl State {
    /// Create new server state.
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            sockets: Default::default(),
        }
    }
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
pub struct Server {}

impl Server {
    /// Create a new server.
    pub async fn new() -> Result<Self> {
        Ok(Self {})
    }

    /// Start the server.
    pub async fn start(
        &self,
        state: ServerState,
        backend: ServerBackend,
        handle: Handle,
    ) -> Result<()> {
        let reader = state.read().await;
        let origins = Server::read_origins(&reader)?;
        let ssl = reader.config.net.ssl.clone();
        let addr = reader.config.bind_address().clone();
        drop(reader);

        match ssl {
            Some(SslConfig::Tls(tls)) => {
                self.run_tls(addr, state, backend, handle, origins, tls)
                    .await
            }
            #[cfg(feature = "acme")]
            Some(SslConfig::Acme(acme)) => {
                self.run_acme(addr, state, backend, handle, origins, acme)
                    .await
            }
            None => self.run(addr, state, backend, handle, origins).await,
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
        let storage = {
            let state = state.read().await;
            let backend = backend.read().await;
            (
                state.config.storage.clone(),
                backend.paths().documents_dir().to_owned(),
            )
        };

        let tls = RustlsConfig::from_pem_file(&tls.cert, &tls.key).await?;
        let app = Server::router(Arc::clone(&state), backend, origins)?;

        self.startup_message(state, &addr, true, storage).await;

        axum_server::bind_rustls(addr, tls)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
        Ok(())
    }

    /// Start the server running on HTTPS using ACME.
    #[cfg(feature = "acme")]
    async fn run_acme(
        &self,
        addr: SocketAddr,
        state: ServerState,
        backend: ServerBackend,
        handle: Handle,
        origins: Vec<HeaderValue>,
        acme: config::AcmeConfig,
    ) -> Result<()> {
        let storage = {
            let state = state.read().await;
            let backend = backend.read().await;
            (
                state.config.storage.clone(),
                backend.paths().documents_dir().to_owned(),
            )
        };

        let mut acme_state = AcmeConfig::new(acme.domains)
            .contact(acme.email.iter().map(|e| format!("mailto:{}", e)))
            .cache_option(Some(DirCache::new(acme.cache)))
            .directory_lets_encrypt(acme.production)
            .state();

        let app = Server::router(Arc::clone(&state), backend, origins)?;

        self.startup_message(state, &addr, true, storage).await;

        let rustls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(acme_state.resolver());
        let acceptor = acme_state.axum_acceptor(Arc::new(rustls_config));

        tokio::spawn(async move {
            loop {
                match acme_state.next().await.unwrap() {
                    Ok(res) => tracing::info!(result = ?res, "acme"),
                    Err(err) => tracing::error!(error = ?err, "acme"),
                }
            }
        });

        axum_server::bind(addr)
            .acceptor(acceptor)
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
        let storage = {
            let state = state.read().await;
            let backend = backend.read().await;
            (
                state.config.storage.clone(),
                backend.paths().documents_dir().to_owned(),
            )
        };

        let app = Server::router(Arc::clone(&state), backend, origins)?;
        self.startup_message(state, &addr, false, storage).await;

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
        storage: (StorageConfig, PathBuf),
    ) {
        let now = UtcDateTime::now().to_rfc3339().unwrap();

        let mut columns = vec![
            ("Started", now),
            ("Listen", addr.to_string()),
            ("TLS enabled", tls.to_string()),
            ("Directory", storage.1.display().to_string()),
        ];

        if let Some(db_file) = &storage.0.database_uri {
            columns.push(("Database", db_file.as_uri_string()));
        }

        let max_length = columns.iter().map(|s| s.0.len()).max().unwrap();
        let col_size = max_length + 4;
        for (key, value) in columns {
            let padding = col_size - key.len();
            println!("{}{}{}", key, " ".repeat(padding), value.yellow());
        }

        {
            let reader = state.read().await;
            if let Some(access) = &reader.config.access {
                if let Some(allow) = &access.allow {
                    for address in allow {
                        println!(
                            "Allow          {}",
                            address.to_string().green()
                        );
                    }
                }
                if let Some(deny) = &access.deny {
                    for address in deny {
                        println!(
                            "Deny           {}",
                            address.to_string().red()
                        );
                    }
                }
            }
        }
    }

    fn read_origins(
        reader: &RwLockReadGuard<'_, State>,
    ) -> Result<Vec<HeaderValue>> {
        let mut origins = Vec::new();
        let cors = reader.config.net.cors.as_ref();
        if let Some(cors) = cors {
            for url in cors.origins.iter() {
                origins.push(HeaderValue::from_str(
                    url.as_str().trim_end_matches('/'),
                )?);
            }
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
                    put(account::create_account)
                        .post(account::update_account)
                        .patch(account::sync_account)
                        .get(account::fetch_account)
                        .head(account::account_exists)
                        .delete(account::delete_account),
                )
                .route("/sync/account/status", get(account::sync_status))
                .route(
                    "/sync/account/events",
                    get(account::event_scan)
                        .post(account::event_diff)
                        .patch(account::event_patch),
                );

            {
                use super::handlers::files::{self, file_operation_lock};
                router = router
                    .route("/sync/files", post(files::compare_files))
                    .route(
                        "/sync/file/{vault_id}/{secret_id}/{file_name}",
                        put(files::receive_file)
                            .post(files::move_file)
                            .get(files::send_file)
                            .delete(files::delete_file)
                            .route_layer(middleware::from_fn(
                                file_operation_lock,
                            )),
                    );
            }

            #[cfg(feature = "listen")]
            {
                use super::handlers::connections;
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

        let mut v1 = v1.layer(cors).layer(
            TraceLayer::new_for_http()
                .on_request(DefaultOnRequest::new().level(Level::TRACE))
                .on_response(DefaultOnResponse::new().level(Level::TRACE)),
        );

        #[cfg(feature = "pairing")]
        {
            let relay: RelayState = Arc::new(Mutex::new(HashMap::new()));
            v1 = v1.layer(Extension(relay));
        }

        v1 = v1.layer(Extension(backend)).layer(Extension(state));

        {
            let file_operations: ServerTransfer =
                Arc::new(RwLock::new(HashSet::new()));
            v1 = v1.layer(Extension(file_operations));
        }

        #[allow(unused_mut)]
        let mut app = Router::new()
            .route("/", get(home))
            .nest_service("/api/v1", v1);

        #[cfg(feature = "prometheus")]
        {
            let (prometheus_layer, metric_handle) =
                axum_prometheus::PrometheusMetricLayerBuilder::new()
                    .with_default_metrics()
                    .enable_response_body_size(true)
                    .build_pair();

            app = app
                .route(
                    "/metrics",
                    get(|| async move { metric_handle.render() }),
                )
                .layer(prometheus_layer);
        }

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
    let value = crate::api_docs::openapi();
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
