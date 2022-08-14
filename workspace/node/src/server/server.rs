use super::{
    authenticate::Authentication,
    handlers::{
        account::AccountHandler,
        api,
        auth::AuthHandler,
        home,
        session::SessionHandler,
        sse::{sse_handler, SseConnection},
        wal::WalHandler,
    },
    headers::{X_COMMIT_PROOF, X_MATCH_PROOF, X_SIGNED_MESSAGE},
    Backend, Result, ServerConfig,
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
use serde::Serialize;
use sos_core::{address::AddressStr, AuditLogFile};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::sync::{RwLock, RwLockReadGuard};
use tower_http::cors::{CorsLayer, Origin};

use crate::session::SessionManager;

/// Server state.
pub struct State {
    /// The server configuration.
    pub config: ServerConfig,
    /// Server information.
    pub info: ServerInfo,
    /// Storage backend.
    pub backend: Box<dyn Backend + Send + Sync>,
    /// Collection of challenges for authentication
    pub authentication: Authentication,
    /// Audit log file
    pub audit_log: AuditLogFile,
    /// Map of server sent event channels by authenticated
    /// client address.
    pub sse: HashMap<AddressStr, SseConnection>,
    /// Session manager.
    pub sessions: SessionManager,
}

/// Server information.
#[derive(Serialize)]
pub struct ServerInfo {
    /// Name of the crate.
    pub name: String,
    /// Version of the crate.
    pub version: String,
}

/// Web server implementation.
pub struct Server;

impl Server {
    /// Create a new server.
    pub fn new() -> Self {
        Self
    }

    /// Start the server running on HTTPS.
    pub async fn start(
        &self,
        addr: SocketAddr,
        state: Arc<RwLock<State>>,
        handle: Handle,
    ) -> Result<()> {
        let reader = state.read().await;
        let origins = Server::read_origins(&reader)?;

        let tls = &reader.config.tls;
        tracing::debug!(certificate = ?tls.cert);
        tracing::debug!(key = ?tls.key);

        let tls = RustlsConfig::from_pem_file(&tls.cert, &tls.key).await?;
        drop(reader);

        // FIXME: start tokio task to reap stale authentication challenges

        let app = Server::router(state, origins)?;
        tracing::info!("listening on {}", addr);
        axum_server::bind_rustls(addr, tls)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
        Ok(())
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    /// Start the server running on HTTP.
    pub async fn start_insecure(
        &self,
        addr: SocketAddr,
        state: Arc<RwLock<State>>,
        handle: Handle,
    ) -> Result<()> {
        let reader = state.read().await;
        let origins = Server::read_origins(&reader)?;
        drop(reader);

        // FIXME: start tokio task to reap stale authentication challenges

        let app = Server::router(state, origins)?;
        tracing::info!("listening on {}", addr);
        axum_server::bind(addr)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
        Ok(())
    }

    fn read_origins<'a>(
        reader: &RwLockReadGuard<'a, State>,
    ) -> Result<Vec<HeaderValue>> {
        let mut origins = Vec::new();
        for url in reader.config.api.origins.iter() {
            origins.push(HeaderValue::from_str(
                url.as_str().trim_end_matches('/'),
            )?);
        }
        Ok(origins)
    }

    fn router(
        state: Arc<RwLock<State>>,
        origins: Vec<HeaderValue>,
    ) -> Result<Router> {
        let cors = CorsLayer::new()
            .allow_methods(vec![
                Method::PUT,
                Method::GET,
                Method::POST,
                Method::DELETE,
                Method::PATCH,
            ])
            // For SSE support must allow credentials
            .allow_credentials(true)
            .allow_headers(vec![
                AUTHORIZATION,
                CONTENT_TYPE,
                X_SIGNED_MESSAGE.clone(),
                X_COMMIT_PROOF.clone(),
                X_MATCH_PROOF.clone(),
            ])
            .expose_headers(vec![
                X_COMMIT_PROOF.clone(),
                X_MATCH_PROOF.clone(),
            ])
            .allow_origin(Origin::list(origins));

        let mut app = Router::new()
            .route("/", get(home))
            .route("/api", get(api))
            .route("/api/auth", get(AuthHandler::challenge))
            .route("/api/auth/:uuid", get(AuthHandler::response))
            .route("/api/accounts", put(AccountHandler::put_account))
            .route("/api/vaults", put(WalHandler::put_wal))
            .route(
                "/api/vaults/:vault_id",
                get(WalHandler::get_wal)
                    .head(WalHandler::head_wal)
                    .post(WalHandler::post_wal)
                    .put(WalHandler::put_vault)
                    .patch(WalHandler::patch_wal)
                    .delete(WalHandler::delete_wal),
            )
            .route("/api/changes", get(sse_handler))
            .route("/api/session", post(SessionHandler::post));

        app = feature_routes(app);
        app = app.layer(cors).layer(Extension(state));

        Ok(app)
    }
}

#[cfg(not(feature = "gui"))]
fn feature_routes(app: Router) -> Router {
    app
}

#[cfg(feature = "gui")]
fn feature_routes(app: Router) -> Router {
    app.route("/gui/*path", get(super::handlers::assets))
}
