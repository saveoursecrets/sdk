use axum::{
    body::{Body, Bytes},
    extract::{Extension, Path, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        HeaderValue, Method, Request, Response, StatusCode,
    },
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Json, Router,
};
use tower_http::cors::{CorsLayer, Origin};

//use axum_macros::debug_handler;

use crate::{
    assets::Assets,
    authenticate::{self, Authentication},
    Backend, ServerConfig,
};
use serde_json::json;
use sos_core::{
    address::AddressStr, decode, encode, k256::ecdsa::recoverable,
    vault::Vault, web3_signature::Signature,
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
    pub backend: Box<dyn Backend + Send + Sync>,
    /// Collection of challenges for authentication
    pub authentication: Authentication,
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
                    .unwrap_or_else(|_| "sos_server=debug".into()),
            ))
            .with(tracing_subscriber::fmt::layer())
            .init();

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
            .allow_methods(vec![Method::GET, Method::POST])
            .allow_headers(vec![AUTHORIZATION, CONTENT_TYPE])
            .allow_origin(Origin::list(origins));

        let app = Router::new()
            .route("/", get(home))
            .route("/gui/*path", get(asset))
            .route("/api", get(api))
            .route("/api/auth", post(AuthHandler::challenge))
            .route("/api/auth/:uuid", post(AuthHandler::response))
            .route("/api/accounts", post(AccountHandler::create))
            .route("/api/accounts/:user", get(VaultHandler::list))
            .route(
                "/api/accounts/:user/vaults/:id",
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
        if path.ends_with('/') {
            path.push_str("index.html");
        }

        let key = path.trim_start_matches("/gui/");
        tracing::debug!(key, "static asset");

        if let Some(asset) = Assets::get(key) {
            let content_type = mime_guess::from_path(key)
                .first()
                .unwrap_or_else(|| "application/octet-stream".parse().unwrap());
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

// Handlers for account operations.
struct AuthHandler;
impl AuthHandler {
    /// Issue an authentication challenge.
    ///
    /// The request must be signed in a Authorization header but
    /// the message is chosen by the client. It is recommended the
    /// client choose a 32 byte random payload.
    ///
    /// The signature allows us to determine if an account exists
    /// before creating a challenge.
    ///
    /// The response is a JSON array tuple containing the challenge
    /// identifier as the first element and the 32 byte message to
    /// be signed as the second element.
    async fn challenge(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        body: Bytes,
    ) -> impl IntoResponse {
        if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &body)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let mut writer = state.write().await;
                if writer.backend.account_exists(&token.address) {
                    let challenge = writer.authentication.new_challenge();
                    (StatusCode::OK, Json(json!(challenge)))
                } else {
                    (StatusCode::NOT_FOUND, Json(json!(null)))
                }
            } else {
                (status_code, Json(json!(null)))
            }
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!(null)))
        }
    }

    /// Handle the response to a challenge.
    async fn response(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        Path(challenge_id): Path<Uuid>,
        body: Bytes,
    ) -> impl IntoResponse {
        let mut writer = state.write().await;

        // Immediately remove the identified challenge so we clean
        // up the server state as early as possible. There is a possible
        // DoS here if an intermediary MiTM detected the challenge identifier
        // and submits it before the real client can authenticate then
        // they can be denied access to the vault list.
        if let Some((challenge, _)) =
            writer.authentication.remove(&challenge_id)
        {
            // Body payload must match the challenge corresponding
            // to it's identifier
            if challenge == body.as_ref() {
                // Now check the bearer signature against the body payload
                if let Ok((status_code, token)) =
                    authenticate::bearer(authorization, &body)
                {
                    if let (StatusCode::OK, Some(token)) = (status_code, token)
                    {
                        if writer.backend.account_exists(&token.address) {
                            // TODO: return list of vaults to the client?
                            StatusCode::OK
                        } else {
                            StatusCode::NOT_FOUND
                        }
                    } else {
                        status_code
                    }
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            } else {
                StatusCode::BAD_REQUEST
            }
        } else {
            StatusCode::NOT_FOUND
        }
    }
}

// Handlers for account operations.
struct AccountHandler;
impl AccountHandler {
    /// Create a new user account.
    async fn create(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        body: Bytes,
    ) -> impl IntoResponse {
        if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &body)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                //println!("Got authorization with {:#?}", token);
                if let Ok(vault) = Vault::read_buffer(&body) {
                    let uuid = vault.id();
                    let mut writer = state.write().await;
                    if let Ok(_) = writer.backend.create_account(
                        token.address,
                        *uuid,
                        &body,
                    ) {
                        StatusCode::OK
                    } else {
                        StatusCode::INTERNAL_SERVER_ERROR
                    }
                } else {
                    StatusCode::BAD_REQUEST
                }
            } else {
                status_code
            }
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
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

        todo!()

        /*
        let (status, value) =
            if let Some(backend) = reader.backends.get(&user_id) {
                let list: Vec<String> =
                    backend.list().iter().map(|k| k.to_string()).collect();
                (StatusCode::OK, json!(list))
            } else {
                (StatusCode::NOT_FOUND, json!(()))
            };
        (status, Json(value))
        */
    }

    /// Retrieve an encrypted vault.
    async fn retrieve_vault(
        Extension(state): Extension<Arc<RwLock<State>>>,
        Path((user_id, vault_id)): Path<(AddressStr, Uuid)>,
    ) -> Result<Bytes, StatusCode> {
        let reader = state.read().await;

        todo!()

        /*
        if let Some(backend) = reader.backends.get(&user_id) {
            if let Ok(Some(vault)) = backend.get(&vault_id) {
                let buffer = encode(&vault)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                Ok(Bytes::from(buffer))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        } else {
            Err(StatusCode::NOT_FOUND)
        }
        */
    }

    /// Update an encrypted vault.
    async fn update_vault(
        Extension(state): Extension<Arc<RwLock<State>>>,
        Path((user_id, vault_id)): Path<(AddressStr, Uuid)>,
        body: Bytes,
    ) -> Result<(), StatusCode> {
        let mut writer = state.write().await;

        todo!()

        /*
        if let Some(backend) = writer.backends.get_mut(&user_id) {
            if let Some(vault) = backend.get_mut(&vault_id) {
                let buffer = body.to_vec();
                let new_vault: Vault = decode(buffer)
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
        */
    }
}
