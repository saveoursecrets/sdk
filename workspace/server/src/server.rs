use axum::{
    extract::{Extension},
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        HeaderValue, Method,
    },
    routing::{get, put}, Router,
};

use tower_http::cors::{CorsLayer, Origin};

//use axum_macros::debug_handler;

use serde::Serialize;

use sos_core::{
    address::AddressStr,
};

use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;

use sos_audit::AuditLogFile;

use crate::{
    authenticate::{Authentication},
    handlers::{
        account::AccountHandler,
        auth::AuthHandler,
        sse::{sse_handler, SseConnection},
        wal::WalHandler,
        home,
        api,
        assets,
    },
    headers::{
        X_COMMIT_HASH,
        X_COMMIT_PROOF, X_SIGNED_MESSAGE,
    },
    Backend, ServerConfig,
};

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
    ) -> crate::Result<()> {
        let shared_state = Arc::clone(&state);

        let reader = shared_state.read().await;
        let mut origins = Vec::new();
        for url in reader.config.api.origins.iter() {
            origins.push(HeaderValue::from_str(
                url.as_str().trim_end_matches('/'),
            )?);
        }

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
                X_COMMIT_HASH.clone(),
                X_COMMIT_PROOF.clone(),
            ])
            .expose_headers(vec![
                X_COMMIT_HASH.clone(),
                X_COMMIT_PROOF.clone(),
            ])
            .allow_origin(Origin::list(origins));

        let app = Router::new()
            .route("/", get(home))
            .route("/gui/*path", get(assets))
            .route("/api", get(api))
            .route("/api/auth", get(AuthHandler::challenge))
            .route("/api/auth/:uuid", get(AuthHandler::response))
            .route("/api/accounts", put(AccountHandler::put_account))
            //.route("/api/vaults", put(VaultHandler::create_vault))
            /*
            .route(
                "/api/vaults/:vault_id",
                get(VaultHandler::read_vault)
                    .head(VaultHandler::head_vault)
                    .delete(VaultHandler::delete_vault)
                    .post(VaultHandler::update_vault)
                    .patch(VaultHandler::patch_vault),
            )
            */
            .route("/api/vaults", put(WalHandler::put_wal))
            .route(
                "/api/vaults/:vault_id",
                get(WalHandler::get_wal)
                    .head(WalHandler::head_wal)
                    .post(WalHandler::post_wal)
                    .patch(WalHandler::patch_wal),
            )
            /*
            .route(
                "/api/vaults/:vault_id/name",
                get(VaultHandler::get_vault_name)
                    .post(VaultHandler::set_vault_name),
            )
            */
            /*
            .route(
                "/api/vaults/:vault_id/secrets/:secret_id",
                put(SecretHandler::create_secret)
                    .get(SecretHandler::read_secret)
                    .post(SecretHandler::update_secret)
                    .delete(SecretHandler::delete_secret),
            )
            */
            .route("/api/changes", get(sse_handler))
            .layer(cors)
            .layer(Extension(shared_state));

        tracing::info!("listening on {}", addr);
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await
            .unwrap();
        Ok(())
    }
}
