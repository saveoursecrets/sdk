use axum::{
    body::Bytes,
    extract::Path,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sos_core::{into_encoded_buffer, vault::Vault};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
};
use uuid::Uuid;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Server state.
pub struct State {
    /// Collection of vaults managed by this server.
    pub vaults: HashMap<Uuid, Vault>,
}

// Server implementation.
pub struct Server;

impl Server {
    pub async fn start(addr: SocketAddr, state: Arc<RwLock<State>>) {
        tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new(
                std::env::var("RUST_LOG").unwrap_or_else(|_| "sos3_server=debug".into()),
            ))
            .with(tracing_subscriber::fmt::layer())
            .init();

        let app = Router::new()
            .route("/", get(home))
            .route(
                "/vault",
                get({
                    let shared_state = Arc::clone(&state);
                    move || VaultHandler::list(Arc::clone(&shared_state))
                }),
            )
            .route(
                "/vault/:id",
                get({
                    let shared_state = Arc::clone(&state);
                    move |path| VaultHandler::get(path, Arc::clone(&shared_state))
                }),
            );

        tracing::debug!("listening on {}", addr);
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await
            .unwrap();
    }
}

// Handler for the server root.
async fn home() -> impl IntoResponse {
    StatusCode::NOT_FOUND
}

// Handlers for vault operations.
struct VaultHandler;
impl VaultHandler {
    /// List vault identifiers.
    async fn list(state: Arc<RwLock<State>>) -> impl IntoResponse {
        let reader = state.read().unwrap();
        let list: Vec<String> = reader.vaults.iter().map(|(k, _)| k.to_string()).collect();
        (StatusCode::OK, Json(list))
    }

    /// Get the encrypted index data for a vault.
    async fn get(
        Path(vault_id): Path<Uuid>,
        state: Arc<RwLock<State>>,
    ) -> Result<Bytes, StatusCode> {
        let reader = state.read().unwrap();
        if let Some(vault) = reader.vaults.get(&vault_id) {
            let index = vault.index();
            let buffer = into_encoded_buffer(index)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            Ok(Bytes::from(buffer))
        } else {
            Err(StatusCode::NOT_FOUND)
        }
    }

    async fn create(Json(payload): Json<CreateVault>) -> impl IntoResponse {
        let vault = VaultInfo {
            label: payload.label,
        };

        (StatusCode::CREATED, Json(vault))
    }
}

#[derive(Deserialize)]
struct CreateVault {
    label: String,
}

#[derive(Serialize)]
struct VaultInfo {
    label: String,
}
