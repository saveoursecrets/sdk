use axum::{
    body::{Body, Bytes},
    extract::{Extension, Path},
    http::{Request, Response, StatusCode},
    response::{IntoResponse, Redirect},
    routing::get,
    Json, Router,
};
//use axum_macros::debug_handler;

//use serde::{Deserialize, Serialize};
use crate::{assets::Assets, Backend, ServerConfig};
use serde_json::json;
use sos_core::{from_encoded_buffer, into_encoded_buffer, vault::Index};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

/// Server state.
pub struct State {
    /// The server configuration.
    pub config: ServerConfig,
    /// Name of the crate.
    pub name: String,
    /// Version of the crate.
    pub version: String,
    /// Determine if we serve the built in GUI.
    pub gui: bool,
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
            .route("/gui/*path", get(asset))
            .route("/api", get(api))
            .route("/api/vault", get(VaultHandler::list))
            .route(
                "/api/vault/:id",
                get(VaultHandler::retrieve_index).post(VaultHandler::update_index),
            )
            .layer(Extension(shared_state));

        tracing::debug!("listening on {}", addr);
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await
            .unwrap();
    }
}

// Serve the home page.
async fn home(Extension(state): Extension<Arc<RwLock<State>>>) -> impl IntoResponse {
    let reader = state.read().await;
    if reader.gui {
        Redirect::temporary("/gui".parse().unwrap())
    } else {
        Redirect::temporary("/api".parse().unwrap())
    }
}

// Serve bundled static assets.
async fn asset(
    Extension(state): Extension<Arc<RwLock<State>>>,
    request: Request<Body>,
) -> Response<Body> {
    let reader = state.read().await;
    if reader.gui {
        let mut path = request.uri().path().to_string();
        if path.ends_with("/") {
            path.push_str("index.html");
        }

        let key = path.trim_start_matches("/gui/");
        tracing::debug!(key, "static asset path");

        if let Some(asset) = Assets::get(key) {
            let content_type = mime_guess::from_path(key)
                .first()
                .unwrap_or("application/octet-stream".parse().unwrap());

            let bytes = Bytes::from(asset.data.as_ref().to_vec());
            Response::builder()
                .header("content-type", content_type.as_ref())
                .status(StatusCode::OK)
                .body(Body::from(bytes))
                .unwrap()
        } else {
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::empty())
                .unwrap()
        }
    } else {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap()
    }
}

// Serve the API identity page.
async fn api(Extension(state): Extension<Arc<RwLock<State>>>) -> impl IntoResponse {
    let reader = state.read().await;
    Json(json!({ "name": reader.name, "version": reader.version }))
}

// Handlers for vault operations.
struct VaultHandler;
impl VaultHandler {
    /// List vault identifiers.
    async fn list(Extension(state): Extension<Arc<RwLock<State>>>) -> impl IntoResponse {
        let reader = state.read().await;
        let list: Vec<String> = reader
            .backend
            .list()
            .iter()
            .map(|k| k.to_string())
            .collect();
        (StatusCode::OK, Json(list))
    }

    /// Retrieve the encrypted index data for a vault.
    async fn retrieve_index(
        Extension(state): Extension<Arc<RwLock<State>>>,
        Path(vault_id): Path<Uuid>,
    ) -> Result<Bytes, StatusCode> {
        let reader = state.read().await;
        if let Some(vault) = reader.backend.get(&vault_id) {
            let index = vault.index();
            let buffer =
                into_encoded_buffer(index).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            Ok(Bytes::from(buffer))
        } else {
            Err(StatusCode::NOT_FOUND)
        }
    }

    /// Update the encrypted index data for a vault.
    async fn update_index(
        Extension(state): Extension<Arc<RwLock<State>>>,
        Path(vault_id): Path<Uuid>,
        body: Bytes,
    ) -> Result<(), StatusCode> {
        let mut writer = state.write().await;
        let id = if let Some(vault) = writer.backend.get_mut(&vault_id) {
            let buffer = body.to_vec();
            let index: Index =
                from_encoded_buffer(buffer).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            vault.set_index(index);
            Some(vault.id().clone())
        } else {
            None
        };

        if let Some(id) = id {
            writer
                .backend
                .flush(&id)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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
