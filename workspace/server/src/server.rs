use axum::{
    body::{Body, Bytes},
    extract::{Extension, Path},
    http::{HeaderValue, Method, Request, Response, StatusCode},
    response::{IntoResponse, Redirect},
    routing::get,
    Json, Router,
};
use tower_http::cors::{CorsLayer, Origin};

//use axum_macros::debug_handler;

use crate::{assets::Assets, Backend, ServerConfig};
use serde_json::json;
use sos_core::{
    address::AddressStr, from_encoded_buffer, into_encoded_buffer, vault::Vault,
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
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
    /// Map of backends for each user.
    pub backends: HashMap<AddressStr, Box<dyn Backend + Send + Sync>>,
}

// Server implementation.
pub struct Server;

impl Server {
    pub async fn start(
        addr: SocketAddr,
        state: Arc<RwLock<State>>,
    ) -> crate::Result<()> {
        tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new(
                std::env::var("RUST_LOG")
                    .unwrap_or_else(|_| "sos3_server=debug".into()),
            ))
            .with(tracing_subscriber::fmt::layer())
            .init();

        let shared_state = Arc::clone(&state);

        let reader = shared_state.read().await;
        let mut origins = Vec::new();
        for url in reader.config.api.origins.iter() {
            origins.push(HeaderValue::from_str(
                url.as_str().trim_end_matches("/"),
            )?);
        }

        drop(reader);

        let cors = CorsLayer::new()
            // allow `GET` and `POST` when accessing the resource
            .allow_methods(vec![Method::GET, Method::POST])
            // allow requests from any origin
            .allow_origin(Origin::list(origins));

        let app = Router::new()
            .route("/", get(home))
            .route("/gui/*path", get(asset))
            .route("/api", get(api))
            .route("/api/users/:user", get(VaultHandler::list))
            .route(
                "/api/users/:user/vaults/:id",
                get(VaultHandler::retrieve_vault)
                    .post(VaultHandler::update_vault),
            )
            .layer(cors)
            .layer(Extension(shared_state));

        tracing::debug!("listening on {}", addr);
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await
            .unwrap();
        Ok(())
    }
}

// Serve the home page.
async fn home(
    Extension(state): Extension<Arc<RwLock<State>>>,
) -> impl IntoResponse {
    let reader = state.read().await;
    if reader.config.gui {
        Redirect::temporary("/gui")
    } else {
        Redirect::temporary("/api")
    }
}

// Serve bundled static assets.
async fn asset(
    Extension(state): Extension<Arc<RwLock<State>>>,
    request: Request<Body>,
) -> Response<Body> {
    let reader = state.read().await;
    if reader.config.gui {
        let mut path = request.uri().path().to_string();
        if path.ends_with("/") {
            path.push_str("index.html");
        }

        let key = path.trim_start_matches("/gui/");
        tracing::debug!(key, "static asset");

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
async fn api(
    Extension(state): Extension<Arc<RwLock<State>>>,
) -> impl IntoResponse {
    let reader = state.read().await;
    Json(json!({ "name": reader.name, "version": reader.version }))
}

// Handlers for vault operations.
struct VaultHandler;
impl VaultHandler {
    /// List vault identifiers for a user account.
    async fn list(
        Extension(state): Extension<Arc<RwLock<State>>>,
        Path(user_id): Path<AddressStr>,
    ) -> impl IntoResponse {
        let reader = state.read().await;
        let (status, value) =
            if let Some(backend) = reader.backends.get(&user_id) {
                let list: Vec<String> =
                    backend.list().iter().map(|k| k.to_string()).collect();
                (StatusCode::OK, json!(list))
            } else {
                (StatusCode::NOT_FOUND, json!(()))
            };
        (status, Json(value))
    }

    /// Retrieve an encrypted vault.
    async fn retrieve_vault(
        Extension(state): Extension<Arc<RwLock<State>>>,
        Path((user_id, vault_id)): Path<(AddressStr, Uuid)>,
    ) -> Result<Bytes, StatusCode> {
        let reader = state.read().await;
        if let Some(backend) = reader.backends.get(&user_id) {
            if let Some(vault) = backend.get(&vault_id) {
                let buffer = into_encoded_buffer(vault)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                Ok(Bytes::from(buffer))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        } else {
            Err(StatusCode::NOT_FOUND)
        }
    }

    /// Update an encrypted vault.
    async fn update_vault(
        Extension(state): Extension<Arc<RwLock<State>>>,
        Path((user_id, vault_id)): Path<(AddressStr, Uuid)>,
        body: Bytes,
    ) -> Result<(), StatusCode> {
        let mut writer = state.write().await;
        if let Some(backend) = writer.backends.get_mut(&user_id) {
            if let Some(vault) = backend.get_mut(&vault_id) {
                let buffer = body.to_vec();
                let new_vault: Vault = from_encoded_buffer(buffer)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                *vault = new_vault;

                backend
                    .flush(&vault_id)
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                Ok(())
            } else {
                Err(StatusCode::NOT_FOUND)
            }
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
