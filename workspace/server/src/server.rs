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

use crate::{assets::Assets, Backend, ServerConfig};
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

        let cors = CorsLayer::new()
            .allow_methods(vec![Method::GET, Method::POST])
            .allow_headers(vec![AUTHORIZATION, CONTENT_TYPE])
            .allow_origin(Origin::list(origins));

        let app = Router::new()
            .route("/", get(home))
            .route("/gui/*path", get(asset))
            .route("/api", get(api))
            .route("/api/users", post(AccountHandler::create))
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

/// Extract a public key and address from the ECDSA signature
/// in the authorization header.
///
/// Decodes the token from base64 and then parses as a JSON representation
/// of a Signature with r, s and v values.
///
/// The signature is then converted to a recoverable signature and the public
/// key is extracted using the body bytes as the message that has been signed.
fn bearer(
    authorization: Authorization<Bearer>,
    body: &Bytes,
) -> crate::Result<(StatusCode, Option<AddressStr>)> {
    let result = if let Ok(value) = base64::decode(authorization.token()) {
        if let Ok(signature) = serde_json::from_slice::<Signature>(&value) {
            let recoverable: recoverable::Signature = signature.try_into()?;
            let pub_key = recoverable.recover_verify_key(body)?;
            let key_bytes: [u8; 33] =
                pub_key.to_bytes().as_slice().try_into()?;
            let addr: AddressStr = (&key_bytes).try_into()?;
            (StatusCode::OK, Some(addr))
        } else {
            (StatusCode::BAD_REQUEST, None)
        }
    } else {
        (StatusCode::BAD_REQUEST, None)
    };

    Ok(result)
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
        if let Ok((status_code, addr)) = bearer(authorization, &body) {
            if let (StatusCode::OK, Some(addr)) = (status_code, addr) {
                println!("Got authorization with {}", addr);
                // TODO: create the account on the backend
                // TODO: create the initial login vault
                StatusCode::OK
            } else {
                status_code
            }
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        }

        //if let Ok(value) = base64::decode(authorization.token()) {
        //if let Ok(signature) = serde_json::from_slice::<Signature>(&value) {
        //let recoverable: recoverable::Signature = signature.try_into().unwrap();
        ////if let Ok(recoverable) = signature.try_into() {
        //println!("Create a new account, sig: {:#?}", signature);
        //println!("Create a new account, sig: {:#?}", recoverable);
        //println!("Create a new account, sig: {:#?}", body.len());

        //let pub_key = recoverable
        //.recover_verify_key(&body)
        //.expect("couldn't recover pubkey");

        //let key_bytes: [u8; 33] = pub_key.to_bytes().as_slice().try_into()
        //.expect("expecting a 33 byte SEC-1 encoded point");
        //let address = address_compressed(&key_bytes).unwrap();

        //println!("Create a new account, pubkey: {:#?}", pub_key);
        //println!("Create a new account, address: {:#?}", address);

        ////} else {
        ////return StatusCode::INTERNAL_SERVER_ERROR;
        ////}
        //} else {
        //return StatusCode::BAD_REQUEST;
        //}
        //} else {
        //return StatusCode::BAD_REQUEST;
        //}

        //StatusCode::NOT_FOUND
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
                let buffer = encode(vault)
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
