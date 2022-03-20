use axum::{
    body::Bytes,
    extract::{Extension, Path},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
//use serde::{Deserialize, Serialize};
use crate::Backend;
use sos_core::into_encoded_buffer;
use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

/// Server state.
pub struct State {
    /// Vault storage backend.
    pub backend: Box<dyn Backend + Send + Sync>,
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

        let shared_state = Arc::clone(&state);

        let app = Router::new()
            .route("/", get(home))
            .route("/vault", get(VaultHandler::list))
            .route(
                "/vault/:id",
                get(VaultHandler::get).post(VaultHandler::post),
            )
            .layer(Extension(shared_state));

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
    async fn list(Extension(state): Extension<Arc<RwLock<State>>>) -> impl IntoResponse {
        let reader = state.read().unwrap();
        let list: Vec<String> = reader
            .backend
            .list()
            .iter()
            .map(|k| k.to_string())
            .collect();
        (StatusCode::OK, Json(list))
    }

    /// GET the encrypted index data for a vault.
    async fn get(
        Extension(state): Extension<Arc<RwLock<State>>>,
        Path(vault_id): Path<Uuid>,
    ) -> Result<Bytes, StatusCode> {
        let reader = state.read().unwrap();
        if let Some(vault) = reader.backend.get(&vault_id) {
            let index = vault.index();
            let buffer =
                into_encoded_buffer(index).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            Ok(Bytes::from(buffer))
        } else {
            Err(StatusCode::NOT_FOUND)
        }
    }

    /// POST the encrypted index data for a vault.
    async fn post(
        Extension(state): Extension<Arc<RwLock<State>>>,
        Path(vault_id): Path<Uuid>,
        body: Bytes,
    ) -> Result<(), StatusCode> {
        let mut writer = state.write().unwrap();
        if let Some(vault) = writer.backend.get_mut(&vault_id) {
            let buffer = body.to_vec();

            // TODO: decode buffer to Index
            // TODO: assign index to vault
            // TODO: flush vault to backing storage

            println!("Got vault bytes {:#?}", buffer.len());
            println!("Got vault bytes {:#?}", buffer);

            Ok(())
        } else {
            Err(StatusCode::NOT_FOUND)
        }
    }

    /*
    async fn create(Json(payload): Json<CreateVault>) -> impl IntoResponse {
        let vault = VaultInfo {
            label: payload.label,
        };

        (StatusCode::CREATED, Json(vault))
    }
    */
}

/*
#[derive(Deserialize)]
struct CreateVault {
    label: String,
}

#[derive(Serialize)]
struct VaultInfo {
    label: String,
}
*/
