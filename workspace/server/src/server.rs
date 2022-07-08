use crate::{
    authenticate::Authentication,
    handlers::{
        account::AccountHandler,
        api, assets,
        auth::AuthHandler,
        home,
        sse::{sse_handler, SseConnection},
        wal::WalHandler,
    },
    headers::{X_COMMIT_PROOF, X_MATCH_PROOF, X_SIGNED_MESSAGE},
    Backend, ServerConfig,
};
use axum::{
    extract::Extension,
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        HeaderValue, Method,
    },
    routing::{get, put},
    Router,
};
use axum_server::{tls_rustls::RustlsConfig, Handle};
use serde::Serialize;
use sos_core::{address::AddressStr, AuditLogFile};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;
use tower_http::cors::{CorsLayer, Origin};

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
}

#[derive(Serialize)]
pub struct ServerInfo {
    /// Name of the crate.
    pub name: String,
    /// Version of the crate.
    pub version: String,
}

// Server implementation.
pub struct Server;

impl Server {
    pub async fn start(
        addr: SocketAddr,
        state: Arc<RwLock<State>>,
        handle: Handle,
    ) -> crate::Result<()> {
        let shared_state = Arc::clone(&state);

        let reader = shared_state.read().await;
        let mut origins = Vec::new();
        for url in reader.config.api.origins.iter() {
            origins.push(HeaderValue::from_str(
                url.as_str().trim_end_matches('/'),
            )?);
        }

        let tls = &reader.config.tls;
        tracing::debug!(certificate = ?tls.cert);
        tracing::debug!(key = ?tls.cert);

        let tls = RustlsConfig::from_pem_file(&tls.cert, &tls.key).await?;

        drop(reader);

        // FIXME: start tokio task to reap stale authentication challenges

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

        let app = Router::new()
            .route("/", get(home))
            .route("/gui/*path", get(assets))
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
                    .patch(WalHandler::patch_wal)
                    .delete(WalHandler::delete_wal),
            )
            .route("/api/changes", get(sse_handler))
            .layer(cors)
            .layer(Extension(shared_state));

        tracing::info!("listening on {}", addr);
        axum_server::bind_rustls(addr, tls)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
        Ok(())
    }
}
