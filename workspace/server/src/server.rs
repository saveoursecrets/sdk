use axum::{
    routing::{get, post},
    http::StatusCode,
    response::IntoResponse,
    extract::{Path},
    Json, Router,
};
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

// Server state.
pub struct State {}

// Server implementation.
pub struct Server;

impl Server {

    pub async fn start(addr: SocketAddr, state: Arc<RwLock<State>>) {
        tracing_subscriber::fmt::init();

        let app = Router::new()
            .route("/", get(home))
            .route("/vault/:id", get({
                let shared_state = Arc::clone(&state);
                move |path| VaultHandler::get(path, Arc::clone(&state))
            }));

        tracing::debug!("listening on {}", addr);
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await
            .unwrap();
    }
}

// Handler for the server root.
async fn home() -> Result<(), StatusCode> {
    Err(StatusCode::NOT_FOUND)
}

// Handlers for vault operations.
struct VaultHandler;
impl VaultHandler {

    async fn get(Path(vault_id): Path<String>, state: Arc<RwLock<State>>) {
        println!("Get vault with id {}", vault_id);
    }

    async fn create(
        Json(payload): Json<CreateVault>,
    ) -> impl IntoResponse {
        let vault = Vault {
            id: 1337,
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
struct Vault {
    id: u64,
    label: String,
}
