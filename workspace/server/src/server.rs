use axum::{
    body::{Body, Bytes},
    extract::{Extension, Path, Query, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::{
        header::{HeaderMap, AUTHORIZATION, CONTENT_TYPE},
        HeaderValue, Method, Request, Response, StatusCode,
    },
    response::{
        sse::{Event, Sse},
        IntoResponse, Redirect,
    },
    routing::{delete, get, patch, post, put},
    Json, Router,
};

use futures::stream::Stream;
use tower_http::cors::{CorsLayer, Origin};

//use axum_macros::debug_handler;

use serde::Serialize;
use serde_json::json;
use sos_core::{
    address::AddressStr,
    audit::{Append, Log},
    crypto::AeadPack,
    decode,
    operations::{Operation, Payload},
    patch::Patch,
    vault::{Header, Summary, Vault},
};
use std::{
    collections::HashMap, convert::Infallible, net::SocketAddr, sync::Arc,
    time::Duration,
};
use tokio::sync::{
    broadcast::{self, Sender},
    RwLock,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

use crate::{
    assets::Assets,
    audit_log::LogFile,
    authenticate::{self, Authentication, SignedQuery},
    headers::{
        ChangeSequence, SignedMessage, X_CHANGE_SEQUENCE, X_SIGNED_MESSAGE,
    },
    Backend, Error, ServerConfig,
};

const MAX_SSE_CONNECTIONS_PER_CLIENT: u8 = 6;

/// Intermediary type used when handling HTTP requests.
struct ResponseEvent {
    /// Audit log record.
    log: Log,
    /// A server event to send to connected clients.
    event: Option<ServerEvent>,
}

/// Internal type used to reflect whether an operation detected
/// a conflict and a 409 conflict response is required.
enum MaybeConflict {
    /// Send a conflict response with the change sequence
    /// in the `x-change-sequence` header.
    Conflict(u32),
    /// No conflict was detected.
    ///
    /// This is a list of events as certain operations such as
    /// PATCH can execute multiple payloads.
    Success(Vec<ResponseEvent>),
}

impl MaybeConflict {
    async fn process(
        state: Arc<RwLock<State>>,
        event: MaybeConflict,
    ) -> Result<(StatusCode, HeaderMap), StatusCode> {
        Ok(match event {
            MaybeConflict::Conflict(change_seq) => {
                let mut headers = HeaderMap::new();
                let x_change_sequence =
                    HeaderValue::from_str(&change_seq.to_string())
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                headers.insert(X_CHANGE_SEQUENCE.clone(), x_change_sequence);
                (StatusCode::CONFLICT, headers)
            }
            MaybeConflict::Success(events) => {
                let mut writer = state.write().await;
                for response_event in events {
                    writer
                        .audit_log
                        .append(response_event.log)
                        .await
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                    if let Some(event) = response_event.event {
                        // Send notification on the SSE channel
                        if let Some(conn) = writer.sse.get(event.address()) {
                            if let Err(_) = conn.tx.send(event) {
                                tracing::debug!(
                                    "server sent events channel dropped"
                                );
                            }
                        }
                    }
                }

                (StatusCode::OK, HeaderMap::new())
            }
        })
    }
}

/// State for the server sent events connection for a single
/// authenticated client.
pub struct SseConnection {
    /// Broadcast sender for server sent events.
    ///
    /// Handlers can send messages via this sender to broadcast
    /// to all the connected server sent events for the client.
    tx: Sender<ServerEvent>,

    /// Number of connected clients, used to know when
    /// the connection state can be disposed of.
    ///
    /// Browsers limit SSE connections per origin to six
    /// so this should be more than enough.
    clients: u8,
}

/// Server state.
pub struct State {
    /// The server configuration.
    pub config: ServerConfig,
    /// Name of the crate.
    pub name: String,
    /// Version of the crate.
    pub version: String,
    /// Storage backend.
    pub backend: Box<dyn Backend + Send + Sync>,
    /// Collection of challenges for authentication
    pub authentication: Authentication,
    /// Audit log file
    pub audit_log: LogFile,
    /// Map of server sent event channels by authenticated
    /// client address.
    pub sse: HashMap<AddressStr, SseConnection>,
}

/// Server notifications sent over the server sent events stream.
#[derive(Debug, Serialize, Clone)]
pub enum ServerEvent {
    CreateVault {
        #[serde(skip)]
        address: AddressStr,
        vault_id: Uuid,
    },
    UpdateVault {
        #[serde(skip)]
        address: AddressStr,
        vault_id: Uuid,
        change_seq: u32,
    },
    DeleteVault {
        #[serde(skip)]
        address: AddressStr,
        vault_id: Uuid,
        change_seq: u32,
    },
    SetVaultName {
        #[serde(skip)]
        address: AddressStr,
        vault_id: Uuid,
        change_seq: u32,
        name: String,
    },
    SetVaultMeta {
        #[serde(skip)]
        address: AddressStr,
        vault_id: Uuid,
        change_seq: u32,
    },
    CreateSecret {
        #[serde(skip)]
        address: AddressStr,
        vault_id: Uuid,
        secret_id: Uuid,
        change_seq: u32,
    },
    UpdateSecret {
        #[serde(skip)]
        address: AddressStr,
        vault_id: Uuid,
        secret_id: Uuid,
        change_seq: u32,
    },
    DeleteSecret {
        #[serde(skip)]
        address: AddressStr,
        vault_id: Uuid,
        secret_id: Uuid,
        change_seq: u32,
    },
}

impl ServerEvent {
    /// Name for the server sent event.
    fn event_name(&self) -> &str {
        match self {
            Self::CreateVault { .. } => "createVault",
            Self::UpdateVault { .. } => "updateVault",
            Self::DeleteVault { .. } => "deleteVault",
            Self::SetVaultName { .. } => "setVaultName",
            Self::SetVaultMeta { .. } => "setVaultMeta",
            Self::CreateSecret { .. } => "createSecret",
            Self::UpdateSecret { .. } => "updateSecret",
            Self::DeleteSecret { .. } => "deleteSecret",
        }
    }

    /// Address of the client that triggered the event.
    fn address(&self) -> &AddressStr {
        match self {
            Self::CreateVault { address, .. } => address,
            Self::UpdateVault { address, .. } => address,
            Self::DeleteVault { address, .. } => address,
            Self::SetVaultName { address, .. } => address,
            Self::SetVaultMeta { address, .. } => address,
            Self::CreateSecret { address, .. } => address,
            Self::UpdateSecret { address, .. } => address,
            Self::DeleteSecret { address, .. } => address,
        }
    }
}

impl TryFrom<ServerEvent> for Event {
    type Error = Error;
    fn try_from(event: ServerEvent) -> std::result::Result<Self, Self::Error> {
        let event_name = event.event_name();
        Ok(Event::default().event(&event_name).json_data(event)?)
    }
}

impl<'u, 'a, 'p> From<(&'u Uuid, &'a AddressStr, &'p Payload<'p>)>
    for ServerEvent
{
    fn from(value: (&'u Uuid, &'a AddressStr, &'p Payload<'p>)) -> Self {
        let (vault_id, address, payload) = value;
        match payload {
            Payload::CreateVault => ServerEvent::CreateVault {
                address: address.clone(),
                vault_id: *vault_id,
            },
            Payload::UpdateVault(change_seq) => ServerEvent::UpdateVault {
                address: address.clone(),
                change_seq: *change_seq,
                vault_id: *vault_id,
            },
            Payload::DeleteVault(change_seq) => ServerEvent::DeleteVault {
                address: address.clone(),
                change_seq: *change_seq,
                vault_id: *vault_id,
            },
            Payload::SetVaultName(change_seq, name) => {
                ServerEvent::SetVaultName {
                    address: address.clone(),
                    change_seq: *change_seq,
                    vault_id: *vault_id,
                    name: name.to_string(),
                }
            }
            Payload::CreateSecret(change_seq, secret_id, _) => {
                ServerEvent::CreateSecret {
                    address: address.clone(),
                    change_seq: *change_seq,
                    vault_id: *vault_id,
                    secret_id: *secret_id,
                }
            }
            Payload::UpdateSecret(change_seq, secret_id, _) => {
                ServerEvent::UpdateSecret {
                    address: address.clone(),
                    change_seq: *change_seq,
                    vault_id: *vault_id,
                    secret_id: *secret_id,
                }
            }
            Payload::DeleteSecret(change_seq, secret_id) => {
                ServerEvent::DeleteSecret {
                    address: address.clone(),
                    change_seq: *change_seq,
                    vault_id: *vault_id,
                    secret_id: *secret_id,
                }
            }
            _ => unreachable!(),
        }
    }
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
                X_CHANGE_SEQUENCE.clone(),
            ])
            .expose_headers(vec![X_CHANGE_SEQUENCE.clone()])
            .allow_origin(Origin::list(origins));

        let app = Router::new()
            .route("/", get(home))
            .route("/gui/*path", get(asset))
            .route("/api", get(api))
            .route("/api/auth", get(AuthHandler::challenge))
            .route("/api/auth/:uuid", get(AuthHandler::response))
            .route("/api/accounts", put(AccountHandler::create))
            .route("/api/vaults", put(VaultHandler::create_vault))
            .route(
                "/api/vaults/:vault_id",
                get(VaultHandler::read_vault)
                    .delete(VaultHandler::delete_vault)
                    .post(VaultHandler::update_vault)
                    .patch(VaultHandler::patch_vault),
            )
            .route(
                "/api/vaults/:vault_id/name",
                get(VaultHandler::get_vault_name)
                    .post(VaultHandler::set_vault_name),
            )
            .route(
                "/api/vaults/:vault_id/secrets/:secret_id",
                put(SecretHandler::create_secret)
                    .get(SecretHandler::read_secret)
                    .post(SecretHandler::update_secret)
                    .delete(SecretHandler::delete_secret),
            )
            .route("/api/changes", get(sse_handler))
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
        TypedHeader(message): TypedHeader<SignedMessage>,
    ) -> Result<Json<(Uuid, [u8; 32])>, StatusCode> {
        if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &message)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let mut writer = state.write().await;
                if writer.backend.account_exists(&token.address).await {
                    let log = Log::new(
                        Operation::LoginChallenge,
                        token.address,
                        None,
                    );
                    writer
                        .audit_log
                        .append(log)
                        .await
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                    let challenge = writer.authentication.new_challenge();
                    Ok(Json(challenge))
                } else {
                    Err(StatusCode::NOT_FOUND)
                }
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }

    /// Handle the response to a challenge.
    async fn response(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(message): TypedHeader<SignedMessage>,
        Path(challenge_id): Path<Uuid>,
    ) -> Result<Json<Vec<Summary>>, StatusCode> {
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
            if challenge == message.as_ref() {
                // Now check the bearer signature against the body payload
                if let Ok((status_code, token)) =
                    authenticate::bearer(authorization, &message)
                {
                    if let (StatusCode::OK, Some(token)) = (status_code, token)
                    {
                        if !writer.backend.account_exists(&token.address).await
                        {
                            return Err(StatusCode::NOT_FOUND);
                        }

                        if let Ok(summaries) =
                            writer.backend.list(&token.address).await
                        {
                            let log = Log::new(
                                Operation::LoginResponse,
                                token.address,
                                None,
                            );
                            writer.audit_log.append(log).await.map_err(
                                |_| StatusCode::INTERNAL_SERVER_ERROR,
                            )?;

                            Ok(Json(summaries))
                        } else {
                            Err(StatusCode::INTERNAL_SERVER_ERROR)
                        }
                    } else {
                        Err(status_code)
                    }
                } else {
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            } else {
                Err(StatusCode::BAD_REQUEST)
            }
        } else {
            Err(StatusCode::NOT_FOUND)
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
    ) -> Result<StatusCode, StatusCode> {
        if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &body)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let mut writer = state.write().await;
                if writer.backend.account_exists(&token.address).await {
                    return Err(StatusCode::CONFLICT);
                }

                if let Ok(vault) = Vault::read_buffer(&body) {
                    let uuid = vault.id();
                    if let Ok(_) = writer
                        .backend
                        .create_account(&token.address, &uuid, &body)
                        .await
                    {
                        let log = Log::new(
                            Operation::CreateAccount,
                            token.address,
                            None,
                        );
                        writer
                            .audit_log
                            .append(log)
                            .await
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                        Ok(StatusCode::OK)
                    } else {
                        Err(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                } else {
                    Err(StatusCode::BAD_REQUEST)
                }
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Handlers for vault operations.
struct VaultHandler;
impl VaultHandler {
    /// Create an encrypted vault.
    async fn create_vault(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        body: Bytes,
    ) -> Result<(StatusCode, HeaderMap), StatusCode> {
        let response = if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &body)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                // Check it looks like a vault payload
                let summary = Header::read_summary_slice(&body)
                    .map_err(|_| StatusCode::BAD_REQUEST)?;

                let reader = state.read().await;
                let (exists, change_seq) = reader
                    .backend
                    .vault_exists(&token.address, summary.id())
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                drop(reader);

                if exists {
                    Ok(MaybeConflict::Conflict(change_seq))
                } else {
                    let mut writer = state.write().await;
                    writer
                        .backend
                        .create_vault(&token.address, summary.id(), &body)
                        .await
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                    let event = ServerEvent::CreateVault {
                        vault_id: *summary.id(),
                        address: token.address.clone(),
                    };

                    let payload = Payload::CreateVault;
                    Ok(MaybeConflict::Success(vec![ResponseEvent {
                        event: Some(event),
                        log: payload
                            .into_audit_log(token.address, *summary.id()),
                    }]))
                }
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        };

        Ok(MaybeConflict::process(state, response?).await?)
    }

    /// Read an encrypted vault.
    async fn read_vault(
        Extension(state): Extension<Arc<RwLock<State>>>,
        Path(vault_id): Path<Uuid>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(message): TypedHeader<SignedMessage>,
    ) -> Result<Bytes, StatusCode> {
        if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &message)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let mut writer = state.write().await;
                if !writer.backend.account_exists(&token.address).await {
                    return Err(StatusCode::NOT_FOUND);
                }

                let (exists, change_seq) = writer
                    .backend
                    .vault_exists(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                if !exists {
                    return Err(StatusCode::NOT_FOUND);
                }

                if let Ok(buffer) =
                    writer.backend.get(&token.address, &vault_id).await
                {
                    let payload = Payload::ReadVault(change_seq);
                    let log = payload.into_audit_log(token.address, vault_id);
                    writer
                        .audit_log
                        .append(log)
                        .await
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                    Ok(Bytes::from(buffer))
                } else {
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }

    /// Delete an encrypted vault.
    async fn delete_vault(
        Extension(state): Extension<Arc<RwLock<State>>>,
        Path(vault_id): Path<Uuid>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(message): TypedHeader<SignedMessage>,
    ) -> Result<(StatusCode, HeaderMap), StatusCode> {
        let response = if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &message)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let mut writer = state.write().await;
                if !writer.backend.account_exists(&token.address).await {
                    return Err(StatusCode::NOT_FOUND);
                }

                let (exists, change_seq) = writer
                    .backend
                    .vault_exists(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                if !exists {
                    return Err(StatusCode::NOT_FOUND);
                }

                if let Ok(_) =
                    writer.backend.get(&token.address, &vault_id).await
                {
                    writer
                        .backend
                        .delete_vault(&token.address, &vault_id)
                        .await
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                    let event = ServerEvent::DeleteVault {
                        vault_id: vault_id.clone(),
                        address: token.address.clone(),
                        change_seq,
                    };

                    let payload = Payload::DeleteVault(change_seq);
                    Ok(MaybeConflict::Success(vec![ResponseEvent {
                        event: Some(event),
                        log: payload.into_audit_log(token.address, vault_id),
                    }]))
                } else {
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        };

        Ok(MaybeConflict::process(state, response?).await?)
    }

    /// Update an encrypted vault.
    async fn update_vault(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(change_seq): TypedHeader<ChangeSequence>,
        Path(vault_id): Path<Uuid>,
        body: Bytes,
    ) -> Result<(StatusCode, HeaderMap), StatusCode> {
        let response = if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &body)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                // Check it looks like a vault payload
                Header::read_summary_slice(&body)
                    .map_err(|_| StatusCode::BAD_REQUEST)?;

                let mut writer = state.write().await;
                let mut handle = writer
                    .backend
                    .vault_write(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::NOT_FOUND)?;

                let local_change_seq: u32 = change_seq.into();
                let remote_change_seq = handle
                    .change_seq()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                if local_change_seq < remote_change_seq {
                    Ok(MaybeConflict::Conflict(remote_change_seq))
                } else {
                    if let Ok(payload) = handle.save(&body) {
                        let event = ServerEvent::from((
                            &vault_id,
                            &token.address,
                            &payload,
                        ));

                        Ok(MaybeConflict::Success(vec![ResponseEvent {
                            event: Some(event),
                            log: payload
                                .into_audit_log(token.address, vault_id),
                        }]))
                    } else {
                        Err(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                }
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        };

        Ok(MaybeConflict::process(state, response?).await?)
    }

    /// Patch an encrypted vault.
    async fn patch_vault(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(change_seq): TypedHeader<ChangeSequence>,
        Path(vault_id): Path<Uuid>,
        body: Bytes,
    ) -> Result<(StatusCode, HeaderMap), StatusCode> {
        let response = if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &body)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let patch: Patch =
                    decode(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

                let mut writer = state.write().await;
                let mut handle = writer
                    .backend
                    .vault_write(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::NOT_FOUND)?;

                let local_change_seq: u32 = change_seq.into();
                let remote_change_seq = handle
                    .change_seq()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                if local_change_seq < remote_change_seq {
                    Ok(MaybeConflict::Conflict(remote_change_seq))
                } else {
                    let change_set: Vec<Payload> = patch.into();

                    let mut events: Vec<ResponseEvent> =
                        Vec::with_capacity(change_set.len());

                    for payload in change_set {
                        if payload.is_mutation() {
                            // FIXME: make this transactional and rollback
                            handle.apply(&payload).map_err(|_| {
                                StatusCode::INTERNAL_SERVER_ERROR
                            })?;

                            events.push(ResponseEvent {
                                event: Some(ServerEvent::from((
                                    &vault_id,
                                    &token.address,
                                    &payload,
                                ))),
                                log: payload
                                    .into_audit_log(token.address, vault_id),
                            });
                        } else {
                            events.push(ResponseEvent {
                                event: None,
                                log: payload
                                    .into_audit_log(token.address, vault_id),
                            });
                        }
                    }
                    Ok(MaybeConflict::Success(events))
                }
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        };

        Ok(MaybeConflict::process(state, response?).await?)
    }

    /// Get the name for a vault.
    async fn get_vault_name(
        Extension(state): Extension<Arc<RwLock<State>>>,
        Path(vault_id): Path<Uuid>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(message): TypedHeader<SignedMessage>,
    ) -> Result<Json<String>, StatusCode> {
        let response = if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &message)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let reader = state.read().await;

                let handle = reader
                    .backend
                    .vault_read(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::NOT_FOUND)?;

                let (name, payload) = handle
                    .vault_name()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                Ok((name, payload.into_audit_log(token.address, vault_id)))
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        };

        let (name, log) = response?;
        let mut writer = state.write().await;
        writer
            .audit_log
            .append(log)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(Json(name))
    }

    /// Set the name for a vault.
    async fn set_vault_name(
        Extension(state): Extension<Arc<RwLock<State>>>,
        Path(vault_id): Path<Uuid>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(message): TypedHeader<SignedMessage>,
        TypedHeader(change_seq): TypedHeader<ChangeSequence>,
        Json(name): Json<String>,
    ) -> Result<(StatusCode, HeaderMap), StatusCode> {
        let response = if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &message)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let mut writer = state.write().await;
                if !writer.backend.account_exists(&token.address).await {
                    return Err(StatusCode::NOT_FOUND);
                }

                let (exists, remote_change_seq) = writer
                    .backend
                    .vault_exists(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                if !exists {
                    return Err(StatusCode::NOT_FOUND);
                }

                let mut handle = writer
                    .backend
                    .vault_write(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::NOT_FOUND)?;

                let local_change_seq: u32 = change_seq.into();
                if local_change_seq != (remote_change_seq + 1) {
                    Ok(MaybeConflict::Conflict(remote_change_seq))
                } else {
                    if let Ok(payload) = handle.set_vault_name(name) {
                        let event = ServerEvent::from((
                            &vault_id,
                            &token.address,
                            &payload,
                        ));

                        Ok(MaybeConflict::Success(vec![ResponseEvent {
                            event: Some(event),
                            log: payload
                                .into_audit_log(token.address, vault_id),
                        }]))
                    } else {
                        Err(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                }
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        };

        Ok(MaybeConflict::process(state, response?).await?)
    }
}

// Handlers for secrets operations.
struct SecretHandler;
impl SecretHandler {
    /// Create an encrypted secret in a vault.
    async fn create_secret(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(change_seq): TypedHeader<ChangeSequence>,
        Path((vault_id, secret_id)): Path<(Uuid, Uuid)>,
        body: Bytes,
    ) -> Result<(StatusCode, HeaderMap), StatusCode> {
        // Perform the creation and get an audit log
        let response = if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &body)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let secret: (AeadPack, AeadPack) =
                    serde_json::from_slice(&body)
                        .map_err(|_| StatusCode::BAD_REQUEST)?;

                let mut writer = state.write().await;
                let mut handle = writer
                    .backend
                    .vault_write(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::NOT_FOUND)?;

                let local_change_seq: u32 = change_seq.into();
                let remote_change_seq = handle
                    .change_seq()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                if local_change_seq != (remote_change_seq + 1) {
                    Ok(MaybeConflict::Conflict(remote_change_seq))
                } else {
                    if let Ok(payload) = handle.create(secret_id, secret) {
                        let event = ServerEvent::from((
                            &vault_id,
                            &token.address,
                            &payload,
                        ));

                        Ok(MaybeConflict::Success(vec![ResponseEvent {
                            event: Some(event),
                            log: payload
                                .into_audit_log(token.address, vault_id),
                        }]))
                    } else {
                        Err(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                }
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        };

        Ok(MaybeConflict::process(state, response?).await?)
    }

    /// Write the audit log for a secret read event.
    async fn read_secret(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(message): TypedHeader<SignedMessage>,
        TypedHeader(change_seq): TypedHeader<ChangeSequence>,
        Path((vault_id, secret_id)): Path<(Uuid, Uuid)>,
    ) -> Result<(StatusCode, HeaderMap), StatusCode> {
        let response = if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &message)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let mut writer = state.write().await;
                let handle = writer
                    .backend
                    .vault_write(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::NOT_FOUND)?;

                let local_change_seq: u32 = change_seq.into();
                let remote_change_seq = handle
                    .change_seq()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                if local_change_seq != remote_change_seq {
                    Ok(MaybeConflict::Conflict(remote_change_seq))
                } else {
                    if let Ok((_, payload)) = handle.read(&secret_id) {
                        Ok(MaybeConflict::Success(vec![ResponseEvent {
                            event: None,
                            log: payload
                                .into_audit_log(token.address, vault_id),
                        }]))
                    } else {
                        Err(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                }
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        };

        Ok(MaybeConflict::process(state, response?).await?)
    }

    /// Update an encrypted secret in a vault.
    async fn update_secret(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(change_seq): TypedHeader<ChangeSequence>,
        Path((vault_id, secret_id)): Path<(Uuid, Uuid)>,
        body: Bytes,
    ) -> Result<(StatusCode, HeaderMap), StatusCode> {
        // Perform the update and get an audit log
        let response = if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &body)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let secret: (AeadPack, AeadPack) =
                    serde_json::from_slice(&body)
                        .map_err(|_| StatusCode::BAD_REQUEST)?;

                let mut writer = state.write().await;
                let mut handle = writer
                    .backend
                    .vault_write(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::NOT_FOUND)?;

                let local_change_seq: u32 = change_seq.into();
                let remote_change_seq = handle
                    .change_seq()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                if local_change_seq != (remote_change_seq + 1) {
                    Ok(MaybeConflict::Conflict(remote_change_seq))
                } else {
                    if let Ok(result) = handle.update(&secret_id, secret) {
                        if let Some(payload) = result {
                            let event = ServerEvent::from((
                                &vault_id,
                                &token.address,
                                &payload,
                            ));

                            Ok(MaybeConflict::Success(vec![ResponseEvent {
                                event: Some(event),
                                log: payload
                                    .into_audit_log(token.address, vault_id),
                            }]))
                        } else {
                            Err(StatusCode::NOT_FOUND)
                        }
                    } else {
                        Err(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                }
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        };

        Ok(MaybeConflict::process(state, response?).await?)
    }

    /// Delete an encrypted secret from a vault.
    async fn delete_secret(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(message): TypedHeader<SignedMessage>,
        TypedHeader(change_seq): TypedHeader<ChangeSequence>,
        Path((vault_id, secret_id)): Path<(Uuid, Uuid)>,
    ) -> Result<(StatusCode, HeaderMap), StatusCode> {
        // Perform the deletion and get an audit log
        let response = if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &message)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let mut writer = state.write().await;
                let mut handle = writer
                    .backend
                    .vault_write(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::NOT_FOUND)?;

                let local_change_seq: u32 = change_seq.into();
                let remote_change_seq = handle
                    .change_seq()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                if local_change_seq != (remote_change_seq + 1) {
                    Ok(MaybeConflict::Conflict(remote_change_seq))
                } else {
                    if let Ok(result) = handle.delete(&secret_id) {
                        if let Some(payload) = result {
                            let event = ServerEvent::from((
                                &vault_id,
                                &token.address,
                                &payload,
                            ));

                            Ok(MaybeConflict::Success(vec![ResponseEvent {
                                event: Some(event),
                                log: payload
                                    .into_audit_log(token.address, vault_id),
                            }]))
                        } else {
                            Err(StatusCode::NOT_FOUND)
                        }
                    } else {
                        Err(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                }
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        };

        Ok(MaybeConflict::process(state, response?).await?)
    }
}

async fn sse_handler(
    Extension(state): Extension<Arc<RwLock<State>>>,
    Query(params): Query<SignedQuery>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    if let Ok((status_code, token)) = params.bearer() {
        if let (StatusCode::OK, Some(token)) = (status_code, token) {
            let address = token.address.clone();
            let stream_state = Arc::clone(&state);
            // Save the sender side of the channel so other handlers
            // can publish to the server sent events stream
            let mut writer = state.write().await;

            let conn = if let Some(conn) = writer.sse.get_mut(&token.address) {
                conn
            } else {
                let (tx, _) = broadcast::channel::<ServerEvent>(256);
                writer
                    .sse
                    .entry(token.address)
                    .or_insert(SseConnection { tx, clients: 0 })
            };

            if let Some(result) = conn.clients.checked_add(1) {
                if result > MAX_SSE_CONNECTIONS_PER_CLIENT {
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
                conn.clients = result;
            } else {
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }

            let mut rx = conn.tx.subscribe();

            struct Guard {
                state: Arc<RwLock<State>>,
                address: AddressStr,
            }

            impl Drop for Guard {
                fn drop(&mut self) {
                    let state = Arc::clone(&self.state);
                    let address = self.address.clone();

                    tokio::spawn(
                        // Clean up the state removing the channel for the
                        // client when the socket is closed.
                        async move {
                            let mut writer = state.write().await;
                            let clients = if let Some(conn) =
                                writer.sse.get_mut(&address)
                            {
                                conn.clients = conn.clients - 1;
                                Some(conn.clients)
                            } else {
                                None
                            };

                            if let Some(clients) = clients {
                                if clients == 0 {
                                    writer.sse.remove(&address);
                                }
                            }
                        },
                    );
                }
            }

            // Publish to the server sent events stream
            let stream = async_stream::stream! {
                let _guard = Guard { state: stream_state, address };
                while let Ok(event) = rx.recv().await {
                    // Must be Infallible here
                    let event: Event = event.try_into().unwrap();
                    tracing::trace!("{:#?}", event);
                    yield Ok(event);
                }
            };

            Ok(Sse::new(stream).keep_alive(
                axum::response::sse::KeepAlive::new()
                    .interval(Duration::from_secs(30))
                    .text("keep-alive"),
            ))
        } else {
            Err(status_code)
        }
    } else {
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}
