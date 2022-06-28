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
    routing::{get, put},
    Json, Router,
};

use futures::stream::Stream;
use tower_http::cors::{CorsLayer, Origin};

//use axum_macros::debug_handler;

use serde_json::json;
use sos_core::{
    address::AddressStr,
    commit_tree::{decode_proof, Comparison},
    decode,
    events::{
        AuditData, AuditEvent, AuditProvider, ChangeEvent, EventKind,
        SyncEvent, WalEvent,
    },
    patch::Patch,
    secret::SecretId,
    vault::{Header, Summary, Vault, VaultCommit},
    wal::{file::WalFileRecord, WalItem},
};

use std::{
    borrow::Cow, collections::HashMap, convert::Infallible, net::SocketAddr,
    sync::Arc, time::Duration,
};
use tokio::sync::{
    broadcast::{self, Sender},
    RwLock,
};
use uuid::Uuid;

use sos_audit::AuditLogFile;

use crate::{
    assets::Assets,
    authenticate::{self, Authentication, SignedQuery},
    headers::{
        ChangeSequence, CommitHash, CommitProof, SignedMessage,
        X_CHANGE_SEQUENCE, X_COMMIT_HASH, X_COMMIT_PROOF, X_SIGNED_MESSAGE,
    },
    Backend, ServerConfig,
};

const MAX_SSE_CONNECTIONS_PER_CLIENT: u8 = 6;

/// Intermediary type used when handling HTTP requests.
struct ResponseEvent {
    /// Audit log record.
    log: AuditEvent,
    /// A server event to send to connected clients.
    event: Option<ChangeEvent>,
}

/// Internal type used to reflect whether an operation detected
/// a conflict and a 409 conflict response is required.
enum MaybeConflict {
    /// Send a conflict response with the change sequence
    /// in the `x-change-sequence` header.
    Conflict(u32),
    /// No conflict was detected.
    ///
    /// This is a list of events as certain events such as
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
                        .append_audit_event(response_event.log)
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
    tx: Sender<ChangeEvent>,

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
    pub audit_log: AuditLogFile,
    /// Map of server sent event channels by authenticated
    /// client address.
    pub sse: HashMap<AddressStr, SseConnection>,
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
                X_CHANGE_SEQUENCE.clone(),
                X_COMMIT_HASH.clone(),
                X_COMMIT_PROOF.clone(),
            ])
            .expose_headers(vec![
                X_CHANGE_SEQUENCE.clone(),
                X_COMMIT_HASH.clone(),
                X_COMMIT_PROOF.clone(),
            ])
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
                    .head(VaultHandler::head_vault)
                    .delete(VaultHandler::delete_vault)
                    .post(VaultHandler::update_vault)
                    .patch(VaultHandler::patch_vault),
            )
            .route(
                "/api/vaults/:vault_id/wal",
                get(WalHandler::read_wal).patch(WalHandler::patch_wal),
            )
            /*
            .route(
                "/api/vaults/:vault_id/name",
                get(VaultHandler::get_vault_name)
                    .post(VaultHandler::set_vault_name),
            )
            */
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

        tracing::info!("listening on {}", addr);
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
            let content_type =
                mime_guess::from_path(key).first().unwrap_or_else(|| {
                    "application/octet-stream".parse().unwrap()
                });

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

// Handlers for account events.
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
                    let log = AuditEvent::new(
                        EventKind::LoginChallenge,
                        token.address,
                        None,
                    );
                    writer
                        .audit_log
                        .append_audit_event(log)
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
                    if let (StatusCode::OK, Some(token)) =
                        (status_code, token)
                    {
                        if !writer
                            .backend
                            .account_exists(&token.address)
                            .await
                        {
                            return Err(StatusCode::NOT_FOUND);
                        }

                        if let Ok(summaries) =
                            writer.backend.list(&token.address).await
                        {
                            let log = AuditEvent::new(
                                EventKind::LoginResponse,
                                token.address,
                                None,
                            );
                            writer
                                .audit_log
                                .append_audit_event(log)
                                .await
                                .map_err(|_| {
                                    StatusCode::INTERNAL_SERVER_ERROR
                                })?;

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

// Handlers for account events.
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
                        let log = AuditEvent::new(
                            EventKind::CreateAccount,
                            token.address,
                            None,
                        );
                        writer
                            .audit_log
                            .append_audit_event(log)
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

// Handlers for vault events.
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

                    let payload =
                        SyncEvent::CreateVault(Cow::Borrowed(&body));

                    let event = ChangeEvent::CreateVault {
                        vault_id: *summary.id(),
                        address: token.address,
                        vault: body.to_vec(),
                    };

                    Ok(MaybeConflict::Success(vec![ResponseEvent {
                        event: Some(event),
                        log: AuditEvent::from_sync_event(
                            &payload,
                            token.address,
                            *summary.id(),
                        ),
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

    /// Get the change sequence for a vault.
    async fn head_vault(
        Extension(state): Extension<Arc<RwLock<State>>>,
        Path(vault_id): Path<Uuid>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(message): TypedHeader<SignedMessage>,
    ) -> Result<(StatusCode, HeaderMap), StatusCode> {
        let response = if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &message)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let reader = state.read().await;
                if !reader.backend.account_exists(&token.address).await {
                    return Err(StatusCode::NOT_FOUND);
                }

                let (exists, change_seq) = reader
                    .backend
                    .vault_exists(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                if !exists {
                    return Err(StatusCode::NOT_FOUND);
                }

                let mut headers = HeaderMap::new();
                let x_change_sequence =
                    HeaderValue::from_str(&change_seq.to_string())
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                headers.insert(X_CHANGE_SEQUENCE.clone(), x_change_sequence);
                Ok((StatusCode::OK, headers))
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        };

        Ok(response?)
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
                //if !writer.backend.account_exists(&token.address).await {
                //return Err(StatusCode::NOT_FOUND);
                //}

                let (exists, change_seq) = writer
                    .backend
                    .vault_exists(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                if !exists {
                    return Err(StatusCode::NOT_FOUND);
                }

                if let Ok(buffer) =
                    writer.backend.get_vault(&token.address, &vault_id).await
                {
                    let payload = SyncEvent::ReadVault(change_seq);
                    let log = AuditEvent::from_sync_event(
                        &payload,
                        token.address,
                        vault_id,
                    );
                    writer
                        .audit_log
                        .append_audit_event(log)
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

                let (exists, change_seq) = writer
                    .backend
                    .vault_exists(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                if !exists {
                    return Err(StatusCode::NOT_FOUND);
                }

                writer
                    .backend
                    .delete_vault(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                let event = ChangeEvent::DeleteVault {
                    vault_id,
                    address: token.address,
                    change_seq,
                };

                let payload = SyncEvent::DeleteVault(change_seq);
                Ok(MaybeConflict::Success(vec![ResponseEvent {
                    event: Some(event),
                    log: AuditEvent::from_sync_event(
                        &payload,
                        token.address,
                        vault_id,
                    ),
                }]))
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
                let (handle, _) = writer
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
                        let event = ChangeEvent::from((
                            &vault_id,
                            &token.address,
                            &payload,
                        ));

                        Ok(MaybeConflict::Success(vec![ResponseEvent {
                            event: Some(event),
                            log: AuditEvent::from_sync_event(
                                &payload,
                                token.address,
                                vault_id,
                            ),
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
                let (handle, _) = writer
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
                    let change_set: Vec<SyncEvent> = patch.into();

                    let mut events: Vec<ResponseEvent> =
                        Vec::with_capacity(change_set.len());

                    for payload in change_set {
                        if payload.is_mutation() {
                            // FIXME: make this transactional and rollback
                            handle.apply(&payload).map_err(|_| {
                                StatusCode::INTERNAL_SERVER_ERROR
                            })?;

                            events.push(ResponseEvent {
                                event: Some(ChangeEvent::from((
                                    &vault_id,
                                    &token.address,
                                    &payload,
                                ))),
                                log: AuditEvent::from_sync_event(
                                    &payload,
                                    token.address,
                                    vault_id,
                                ),
                            });
                        } else {
                            events.push(ResponseEvent {
                                event: None,
                                log: AuditEvent::from_sync_event(
                                    &payload,
                                    token.address,
                                    vault_id,
                                ),
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

    /*
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

                let (handle, _) = reader
                    .backend
                    .vault_read(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::NOT_FOUND)?;

                let (name, payload) = handle
                    .vault_name()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                Ok((
                    name,
                    AuditEvent::from_sync_event(
                        &payload,
                        token.address,
                        vault_id,
                    ),
                ))
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
            .append_audit_event(log)
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

                let (handle, _) = writer
                    .backend
                    .vault_write(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::NOT_FOUND)?;

                let local_change_seq: u32 = change_seq.into();
                if local_change_seq != (remote_change_seq + 1) {
                    Ok(MaybeConflict::Conflict(remote_change_seq))
                } else {
                    if let Ok(payload) = handle.set_vault_name(name) {
                        let event = ChangeEvent::from((
                            &vault_id,
                            &token.address,
                            &payload,
                        ));

                        Ok(MaybeConflict::Success(vec![ResponseEvent {
                            event: Some(event),
                            log: AuditEvent::from_sync_event(
                                &payload,
                                token.address,
                                vault_id,
                            ),
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
    */
}

// Handlers for secrets events.
struct SecretHandler;
impl SecretHandler {
    /// Create an encrypted secret in a vault.
    async fn create_secret(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(change_seq): TypedHeader<ChangeSequence>,
        Path((vault_id, secret_id)): Path<(Uuid, SecretId)>,
        body: Bytes,
    ) -> Result<(StatusCode, HeaderMap), StatusCode> {
        // Perform the creation and get an audit log
        let response = if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &body)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let secret: VaultCommit = serde_json::from_slice(&body)
                    .map_err(|_| StatusCode::BAD_REQUEST)?;

                let mut writer = state.write().await;
                let (handle, _) = writer
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
                    if let Ok(payload) = handle.create(secret.0, secret.1) {
                        // TODO: ensure the payload generate secret id
                        // TODO: matches the client supplied id

                        let event = ChangeEvent::from((
                            &vault_id,
                            &token.address,
                            &payload,
                        ));

                        Ok(MaybeConflict::Success(vec![ResponseEvent {
                            event: Some(event),
                            log: AuditEvent::from_sync_event(
                                &payload,
                                token.address,
                                vault_id,
                            ),
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
        Path((vault_id, secret_id)): Path<(Uuid, SecretId)>,
    ) -> Result<(StatusCode, HeaderMap), StatusCode> {
        let response = if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &message)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let mut writer = state.write().await;
                let (handle, _) = writer
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
                            log: AuditEvent::from_sync_event(
                                &payload,
                                token.address,
                                vault_id,
                            ),
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
        Path((vault_id, secret_id)): Path<(Uuid, SecretId)>,
        body: Bytes,
    ) -> Result<(StatusCode, HeaderMap), StatusCode> {
        // Perform the update and get an audit log
        let response = if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &body)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let secret: VaultCommit = serde_json::from_slice(&body)
                    .map_err(|_| StatusCode::BAD_REQUEST)?;

                let mut writer = state.write().await;
                let (handle, _) = writer
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
                    if let Ok(result) =
                        handle.update(&secret_id, secret.0, secret.1)
                    {
                        if let Some(payload) = result {
                            let event = ChangeEvent::from((
                                &vault_id,
                                &token.address,
                                &payload,
                            ));

                            Ok(MaybeConflict::Success(vec![ResponseEvent {
                                event: Some(event),
                                log: AuditEvent::from_sync_event(
                                    &payload,
                                    token.address,
                                    vault_id,
                                ),
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
        Path((vault_id, secret_id)): Path<(Uuid, SecretId)>,
    ) -> Result<(StatusCode, HeaderMap), StatusCode> {
        // Perform the deletion and get an audit log
        let response = if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &message)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let mut writer = state.write().await;
                let (handle, _) = writer
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
                            let event = ChangeEvent::from((
                                &vault_id,
                                &token.address,
                                &payload,
                            ));

                            Ok(MaybeConflict::Success(vec![ResponseEvent {
                                event: Some(event),
                                log: AuditEvent::from_sync_event(
                                    &payload,
                                    token.address,
                                    vault_id,
                                ),
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

        MaybeConflict::process(state, response?).await
    }
}

// Handlers for WAL log events.
struct WalHandler;
impl WalHandler {
    /// Read the buffer of a WAL file.
    ///
    /// If an `x-commit-hash` header is present then we attempt to
    /// fetch a tail of the log after the `x-commit-hash` record.
    ///
    /// When the `x-commit-hash` header is given the `x-commit-proof`
    /// header must also be sent.
    ///
    /// If neither header is present then the entire contents of the
    /// WAL file are returned.
    ///
    /// If an `x-commit-hash` header is present but the WAL does
    /// not contain the leaf node specified in `x-commit-proof` then
    /// a CONFLICT status code is returned.
    ///
    /// The `x-commit-hash` MUST be the root hash in the client WAL
    /// log and the `x-commit-proof` MUST contain the merkle proof for the
    /// most recent leaf node on the client.
    ///
    /// If the client and server root hashes match then a NOT_MODIFIED
    /// status code is returned.
    async fn read_wal(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(message): TypedHeader<SignedMessage>,
        root_hash: Option<TypedHeader<CommitHash>>,
        commit_proof: Option<TypedHeader<CommitProof>>,
        Path(vault_id): Path<Uuid>,
    ) -> Result<Bytes, StatusCode> {
        if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &message)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let reader = state.read().await;

                let (_, wal) = reader
                    .backend
                    .vault_read(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::NOT_FOUND)?;

                // Client is asking for data from a specific commit hash
                let buffer = if let Some(TypedHeader(root_hash)) = root_hash {
                    let root_hash: [u8; 32] = root_hash.into();
                    if let Some(TypedHeader(commit_proof)) = commit_proof {
                        let proof = decode_proof(commit_proof.as_ref())
                            .map_err(|_| StatusCode::BAD_REQUEST)?;

                        let comparison = wal
                            .tree()
                            .compare(root_hash, proof)
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                        match comparison {
                            Comparison::Equal => {
                                Err(StatusCode::NOT_MODIFIED)
                            }
                            Comparison::Contains(_, leaf) => {
                                if let Some(partial) =
                                    wal.diff(leaf).map_err(|_| {
                                        StatusCode::INTERNAL_SERVER_ERROR
                                    })?
                                {
                                    Ok(partial)
                                // Could not find a record corresponding
                                // to the leaf node
                                } else {
                                    Err(StatusCode::CONFLICT)
                                }
                            }
                            // Could not find leaf node in the commit tree
                            Comparison::Unknown => Err(StatusCode::CONFLICT),
                        }
                    } else {
                        Err(StatusCode::BAD_REQUEST)
                    }
                // Otherwise get the entire WAL buffer
                } else {
                    if let Ok(buffer) = reader
                        .backend
                        .get_wal(&token.address, &vault_id)
                        .await
                    {
                        Ok(buffer)
                    } else {
                        Err(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                };

                let mut writer = state.write().await;
                let log = AuditEvent::new(
                    EventKind::ReadWal,
                    token.address,
                    Some(AuditData::Vault(vault_id)),
                );
                writer
                    .audit_log
                    .append_audit_event(log)
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                Ok(Bytes::from(buffer?))
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }

    /// Attempt to append to a WAL file.
    async fn patch_wal(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(root_hash): TypedHeader<CommitHash>,
        TypedHeader(commit_proof): TypedHeader<CommitProof>,
        Path(vault_id): Path<Uuid>,
        body: Bytes,
    ) -> Result<StatusCode, StatusCode> {
        if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &body)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let mut writer = state.write().await;
                let (_, wal) = writer
                    .backend
                    .vault_write(&token.address, &vault_id)
                    .await
                    .map_err(|_| StatusCode::NOT_FOUND)?;

                let root_hash: [u8; 32] = root_hash.into();
                let proof = decode_proof(commit_proof.as_ref())
                    .map_err(|_| StatusCode::BAD_REQUEST)?;

                let comparison = wal
                    .tree()
                    .compare(root_hash, proof)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                let result = match comparison {
                    Comparison::Equal => {
                        let patch: Patch = decode(&body)
                            .map_err(|_| StatusCode::BAD_REQUEST)?;

                        let change_set: Vec<SyncEvent> = patch.into();
                        let audit_logs = change_set
                            .iter()
                            .map(|event| {
                                AuditEvent::from_sync_event(
                                    event,
                                    token.address,
                                    vault_id,
                                )
                            })
                            .collect::<Vec<_>>();

                        let mut changes = Vec::new();
                        for event in change_set {
                            if let Ok::<WalEvent<'_>, sos_core::Error>(
                                wal_event,
                            ) = event.try_into()
                            {
                                changes.push(wal_event);
                            }
                        }

                        todo!("apply the WAL changes");

                        Ok((audit_logs))
                    }
                    Comparison::Contains(_, leaf) => {
                        // Client should attempt to synchronize
                        // before applying a patch
                        Err(StatusCode::CONFLICT)
                    }
                    // Could not find leaf node in the commit tree
                    Comparison::Unknown => Err(StatusCode::CONFLICT),
                };

                let (logs) = result?;

                for log in logs {
                    writer
                        .audit_log
                        .append_audit_event(log)
                        .await
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                }

                Ok(StatusCode::OK)
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn sse_handler(
    Extension(state): Extension<Arc<RwLock<State>>>,
    Query(params): Query<SignedQuery>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    if let Ok((status_code, token)) = params.bearer() {
        if let (StatusCode::OK, Some(token)) = (status_code, token) {
            let address = token.address;
            let stream_state = Arc::clone(&state);
            // Save the sender side of the channel so other handlers
            // can publish to the server sent events stream
            let mut writer = state.write().await;

            let conn = if let Some(conn) = writer.sse.get_mut(&token.address)
            {
                conn
            } else {
                let (tx, _) = broadcast::channel::<ChangeEvent>(256);
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
                    let address = self.address;

                    tokio::spawn(
                        // Clean up the state removing the channel for the
                        // client when the socket is closed.
                        async move {
                            let mut writer = state.write().await;
                            let clients = if let Some(conn) =
                                writer.sse.get_mut(&address)
                            {
                                conn.clients -= 1;
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
                    let event_name = event.event_name();
                    let event = Event::default()
                        .event(&event_name)
                        .json_data(event)
                        .unwrap();
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
