use super::{authenticate_endpoint, Caller};
use axum::{
    body::{to_bytes, Body},
    extract::{Extension, OriginalUri, Query},
    http::StatusCode,
    response::IntoResponse,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    typed_header::TypedHeader,
};

//use axum_macros::debug_handler;

use super::BODY_LIMIT;
use crate::{handlers::ConnectionQuery, ServerBackend, ServerState};

use std::sync::Arc;

/// Determine if an account exists.
#[utoipa::path(
    head,
    path = "/sync/account",
    responses(
        (
            status = StatusCode::OK,
            description = "Account exists.",
        ),
        (
            status = StatusCode::NOT_FOUND,
            description = "Account does not exist.",
        ),
    ),
)]
pub(crate) async fn account_exists(
    Extension(state): Extension<ServerState>,
    Extension(backend): Extension<ServerBackend>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    OriginalUri(uri): OriginalUri,
) -> impl IntoResponse {
    let uri = uri.path().to_string();
    match authenticate_endpoint(
        bearer,
        uri.as_bytes(),
        None,
        Arc::clone(&state),
        Arc::clone(&backend),
        false,
    )
    .await
    {
        Ok(caller) => {
            match handlers::account_exists(state, backend, caller).await {
                Ok(exists) => {
                    if exists {
                        StatusCode::OK.into_response()
                    } else {
                        StatusCode::NOT_FOUND.into_response()
                    }
                }
                Err(error) => error.into_response(),
            }
        }
        Err(error) => error.into_response(),
    }
}

/// Create an account.
#[utoipa::path(
    put,
    path = "/sync/account",
    security(
        ("bearer_token" = [])
    ),
    request_body(
        description = "Protobuf encoded CreateSet",
        content_type = "application/octet-stream",
        content = Vec<u8>,
    ),
    responses(
        (
            status = StatusCode::UNAUTHORIZED,
            description = "Authorization failed.",
        ),
        (
            status = StatusCode::FORBIDDEN,
            description = "Account address is not allowed on this server.",
        ),
        (
            status = StatusCode::CONFLICT,
            description = "Account already exists.",
        ),
        (
            status = StatusCode::OK,
            description = "Account was created.",
        ),
    ),
)]
pub(crate) async fn create_account(
    Extension(state): Extension<ServerState>,
    Extension(backend): Extension<ServerBackend>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    Query(query): Query<ConnectionQuery>,
    body: Body,
) -> impl IntoResponse {
    match to_bytes(body, BODY_LIMIT).await {
        Ok(bytes) => match authenticate_endpoint(
            bearer,
            &bytes,
            Some(query),
            Arc::clone(&state),
            Arc::clone(&backend),
            false,
        )
        .await
        {
            Ok(caller) => {
                match handlers::create_account(state, backend, caller, bytes)
                    .await
                {
                    Ok(result) => result.into_response(),
                    Err(error) => error.into_response(),
                }
            }
            Err(error) => error.into_response(),
        },
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

/// Delete an existing account.
#[utoipa::path(
    delete,
    path = "/sync/account",
    responses(
        (
            status = StatusCode::UNAUTHORIZED,
            description = "Authorization failed.",
        ),
        (
            status = StatusCode::FORBIDDEN,
            description = "Account address is not allowed on this server.",
        ),
        (
            status = StatusCode::NOT_FOUND,
            description = "Account does not exist.",
        ),
        (
            status = StatusCode::OK,
            description = "Account deleted.",
        ),
    ),
)]
pub(crate) async fn delete_account(
    Extension(state): Extension<ServerState>,
    Extension(backend): Extension<ServerBackend>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    OriginalUri(uri): OriginalUri,
) -> impl IntoResponse {
    let uri = uri.path().to_string();
    match authenticate_endpoint(
        bearer,
        uri.as_bytes(),
        None,
        Arc::clone(&state),
        Arc::clone(&backend),
        false,
    )
    .await
    {
        Ok(caller) => {
            match handlers::delete_account(state, backend, caller).await {
                Ok(result) => result.into_response(),
                Err(error) => error.into_response(),
            }
        }
        Err(error) => error.into_response(),
    }
}

/// Update an account.
#[utoipa::path(
    post,
    path = "/sync/account",
    security(
        ("bearer_token" = [])
    ),
    request_body(
        description = "Protobuf encoded CreateSet",
        content_type = "application/octet-stream",
        content = Vec<u8>,
    ),
    responses(
        (
            status = StatusCode::UNAUTHORIZED,
            description = "Authorization failed.",
        ),
        (
            status = StatusCode::FORBIDDEN,
            description = "Account address is not allowed on this server.",
        ),
        (
            status = StatusCode::NOT_FOUND,
            description = "Account does not exist.",
        ),
        (
            status = StatusCode::OK,
            description = "Account was updated.",
        ),
    ),
)]
pub(crate) async fn update_account(
    Extension(state): Extension<ServerState>,
    Extension(backend): Extension<ServerBackend>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    Query(query): Query<ConnectionQuery>,
    body: Body,
) -> impl IntoResponse {
    match to_bytes(body, BODY_LIMIT).await {
        Ok(bytes) => match authenticate_endpoint(
            bearer,
            &bytes,
            Some(query),
            Arc::clone(&state),
            Arc::clone(&backend),
            true,
        )
        .await
        {
            Ok(caller) => {
                match handlers::update_account(state, backend, caller, bytes)
                    .await
                {
                    Ok(result) => result.into_response(),
                    Err(error) => error.into_response(),
                }
            }
            Err(error) => error.into_response(),
        },
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

/// Fetch an account.
#[utoipa::path(
    get,
    path = "/sync/account",
    security(
        ("bearer_token" = [])
    ),
    responses(
        (
            status = StatusCode::UNAUTHORIZED,
            description = "Authorization failed.",
        ),
        (
            status = StatusCode::FORBIDDEN,
            description = "Account address is not allowed on this server.",
        ),
        (
            status = StatusCode::OK,
            content_type = "application/octet-stream",
            description = "Account data sent as protobuf-encoded CreateSet.",
            body = Vec<u8>,
        ),
    ),
)]
pub(crate) async fn fetch_account(
    Extension(state): Extension<ServerState>,
    Extension(backend): Extension<ServerBackend>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    Query(query): Query<ConnectionQuery>,
    OriginalUri(uri): OriginalUri,
) -> impl IntoResponse {
    let uri = uri.path().to_string();
    match authenticate_endpoint(
        bearer,
        uri.as_bytes(),
        Some(query),
        Arc::clone(&state),
        Arc::clone(&backend),
        true,
    )
    .await
    {
        Ok(caller) => {
            match handlers::fetch_account(state, backend, caller).await {
                Ok(result) => result.into_response(),
                Err(error) => error.into_response(),
            }
        }
        Err(error) => error.into_response(),
    }
}

/// Get account sync status.
#[utoipa::path(
    get,
    path = "/sync/account/status",
    security(
        ("bearer_token" = [])
    ),
    responses(
        (
            status = StatusCode::UNAUTHORIZED,
            description = "Authorization failed.",
        ),
        (
            status = StatusCode::FORBIDDEN,
            description = "Account address is not allowed on this server.",
        ),
        (
            status = StatusCode::OK,
            content_type = "application/octet-stream",
            description = "Account sync status sent as protobuf-encoded SyncStatus",
            body = Vec<u8>,
        ),
    ),
)]
pub(crate) async fn sync_status(
    Extension(state): Extension<ServerState>,
    Extension(backend): Extension<ServerBackend>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    Query(query): Query<ConnectionQuery>,
    OriginalUri(uri): OriginalUri,
) -> impl IntoResponse {
    let uri = uri.path().to_string();
    match authenticate_endpoint(
        bearer,
        uri.as_bytes(),
        Some(query),
        Arc::clone(&state),
        Arc::clone(&backend),
        true,
    )
    .await
    {
        Ok(caller) => {
            match handlers::sync_status(state, backend, caller).await {
                Ok(result) => result.into_response(),
                Err(error) => error.into_response(),
            }
        }
        Err(e) => e.into_response(),
    }
}

/// Scan account event logs for commit proofs.
#[utoipa::path(
    get,
    path = "/sync/account/events",
    security(
        ("bearer_token" = [])
    ),
    request_body(
        description = "Protobuf encoded ScanRequest",
        content_type = "application/octet-stream",
        content = Vec<u8>,
    ),
    responses(
        (
            status = StatusCode::UNAUTHORIZED,
            description = "Authorization failed.",
        ),
        (
            status = StatusCode::FORBIDDEN,
            description = "Account address is not allowed on this server.",
        ),
        (
            status = StatusCode::OK,
            content_type = "application/octet-stream",
            description = "Commit hashes sent as protobuf-encoded ScanResponse.",
            body = Vec<u8>,
        ),
    ),
)]
pub(crate) async fn event_scan(
    Extension(state): Extension<ServerState>,
    Extension(backend): Extension<ServerBackend>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    Query(query): Query<ConnectionQuery>,
    body: Body,
) -> impl IntoResponse {
    match to_bytes(body, BODY_LIMIT).await {
        Ok(bytes) => match authenticate_endpoint(
            bearer,
            &bytes,
            Some(query),
            Arc::clone(&state),
            Arc::clone(&backend),
            true,
        )
        .await
        {
            Ok(caller) => {
                match handlers::event_scan(state, backend, caller, bytes)
                    .await
                {
                    Ok(result) => result.into_response(),
                    Err(error) => error.into_response(),
                }
            }
            Err(error) => error.into_response(),
        },
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

/// Fetch a diff from an event log.
#[utoipa::path(
    post,
    path = "/sync/account/events",
    security(
        ("bearer_token" = [])
    ),
    request_body(
        description = "Protobuf encoded DiffRequest",
        content_type = "application/octet-stream",
        content = Vec<u8>,
    ),
    responses(
        (
            status = StatusCode::UNAUTHORIZED,
            description = "Authorization failed.",
        ),
        (
            status = StatusCode::FORBIDDEN,
            description = "Account address is not allowed on this server.",
        ),
        (
            status = StatusCode::OK,
            content_type = "application/octet-stream",
            description = "Commit diff sent as protobuf-encoded DiffResponse.",
            body = Vec<u8>,
        ),
    ),
)]
pub(crate) async fn event_diff(
    Extension(state): Extension<ServerState>,
    Extension(backend): Extension<ServerBackend>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    Query(query): Query<ConnectionQuery>,
    body: Body,
) -> impl IntoResponse {
    match to_bytes(body, BODY_LIMIT).await {
        Ok(bytes) => match authenticate_endpoint(
            bearer,
            &bytes,
            Some(query),
            Arc::clone(&state),
            Arc::clone(&backend),
            true,
        )
        .await
        {
            Ok(caller) => {
                match handlers::event_diff(state, backend, caller, bytes)
                    .await
                {
                    Ok(result) => result.into_response(),
                    Err(error) => error.into_response(),
                }
            }
            Err(error) => error.into_response(),
        },
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

/// Patch an event log.
#[utoipa::path(
    patch,
    path = "/sync/account/events",
    security(
        ("bearer_token" = [])
    ),
    request_body(
        description = "Protobuf encoded PatchRequest",
        content_type = "application/octet-stream",
        content = Vec<u8>,
    ),
    responses(
        (
            status = StatusCode::UNAUTHORIZED,
            description = "Authorization failed.",
        ),
        (
            status = StatusCode::FORBIDDEN,
            description = "Account address is not allowed on this server.",
        ),
        (
            status = StatusCode::OK,
            content_type = "application/octet-stream",
            description = "Result of the attempt to apply the checked patch as a protobuf-encoded PatchResponse.",
            body = Vec<u8>,
        ),
    ),
)]
pub(crate) async fn event_patch(
    Extension(state): Extension<ServerState>,
    Extension(backend): Extension<ServerBackend>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    Query(query): Query<ConnectionQuery>,
    body: Body,
) -> impl IntoResponse {
    match to_bytes(body, BODY_LIMIT).await {
        Ok(bytes) => match authenticate_endpoint(
            bearer,
            &bytes,
            Some(query),
            Arc::clone(&state),
            Arc::clone(&backend),
            true,
        )
        .await
        {
            Ok(caller) => {
                match handlers::event_patch(state, backend, caller, bytes)
                    .await
                {
                    Ok(result) => result.into_response(),
                    Err(error) => error.into_response(),
                }
            }
            Err(error) => error.into_response(),
        },
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

/// Sync account event logs.
#[utoipa::path(
    patch,
    path = "/sync/account",
    security(
        ("bearer_token" = [])
    ),
    request_body(
        description = "Protobuf encoded SyncPacket",
        content_type = "application/octet-stream",
        content = Vec<u8>,
    ),
    responses(
        (
            status = StatusCode::UNAUTHORIZED,
            description = "Authorization failed.",
        ),
        (
            status = StatusCode::FORBIDDEN,
            description = "Account address is not allowed on this server.",
        ),
        (
            status = StatusCode::OK,
            content_type = "application/octet-stream",
            description = "Account event logs as protobuf-encoded SyncPacket",
            body = Vec<u8>,
        ),
    ),
)]
pub(crate) async fn sync_account(
    Extension(state): Extension<ServerState>,
    Extension(backend): Extension<ServerBackend>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    Query(query): Query<ConnectionQuery>,
    body: Body,
) -> impl IntoResponse {
    match to_bytes(body, BODY_LIMIT).await {
        Ok(bytes) => match authenticate_endpoint(
            bearer,
            &bytes,
            Some(query),
            Arc::clone(&state),
            Arc::clone(&backend),
            true,
        )
        .await
        {
            Ok(caller) => {
                match handlers::sync_account(state, backend, caller, bytes)
                    .await
                {
                    Ok(result) => result.into_response(),
                    Err(error) => error.into_response(),
                }
            }
            Err(error) => error.into_response(),
        },
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

mod handlers {
    use super::Caller;
    use crate::{Error, Result, ServerBackend, ServerState};
    use axum::body::Bytes;
    use http::{
        header::{self, HeaderMap, HeaderValue},
        StatusCode,
    };
    use sos_protocol::{
        sdk::constants::MIME_TYPE_PROTOBUF, server_helpers, CreateSet,
        DiffRequest, PatchRequest, ScanRequest, SyncPacket, SyncStorage,
        UpdateSet, WireEncodeDecode,
    };

    use std::sync::Arc;

    #[cfg(feature = "listen")]
    use sos_protocol::ChangeNotification;

    #[cfg(feature = "listen")]
    use crate::handlers::send_notification;

    pub(super) async fn account_exists(
        _state: ServerState,
        backend: ServerBackend,
        caller: Caller,
    ) -> Result<bool> {
        let reader = backend.read().await;
        reader.account_exists(caller.address()).await
    }

    pub(super) async fn create_account(
        _state: ServerState,
        backend: ServerBackend,
        caller: Caller,
        bytes: Bytes,
    ) -> Result<()> {
        {
            let reader = backend.read().await;
            if reader.account_exists(caller.address()).await? {
                return Err(Error::Conflict);
            }
        }

        let account = CreateSet::decode(bytes).await?;
        let mut writer = backend.write().await;
        writer.create_account(caller.address(), account).await?;
        Ok(())
    }

    pub(super) async fn delete_account(
        _state: ServerState,
        backend: ServerBackend,
        caller: Caller,
    ) -> Result<()> {
        let mut writer = backend.write().await;
        writer.delete_account(caller.address()).await?;
        Ok(())
    }

    pub(super) async fn update_account(
        _state: ServerState,
        backend: ServerBackend,
        caller: Caller,
        bytes: Bytes,
    ) -> Result<()> {
        let account = UpdateSet::decode(bytes).await?;
        let mut writer = backend.write().await;
        writer.update_account(caller.address(), account).await?;
        Ok(())
    }

    pub(super) async fn fetch_account(
        _state: ServerState,
        backend: ServerBackend,
        caller: Caller,
    ) -> Result<(HeaderMap, Vec<u8>)> {
        let reader = backend.read().await;
        let account: CreateSet =
            reader.fetch_account(caller.address()).await?;

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_PROTOBUF),
        );

        Ok((headers, account.encode().await?))
    }

    pub(super) async fn sync_status(
        _state: ServerState,
        backend: ServerBackend,
        caller: Caller,
    ) -> Result<(HeaderMap, Vec<u8>)> {
        let reader = backend.read().await;
        if !reader.account_exists(caller.address()).await? {
            return Err(Error::Status(StatusCode::NOT_FOUND));
        }

        let accounts = reader.accounts();
        let reader = accounts.read().await;
        let account = reader.get(caller.address()).unwrap();
        let account = account.read().await;
        let status = account.storage.sync_status().await?;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_PROTOBUF),
        );
        Ok((headers, status.encode().await?))
    }

    pub(super) async fn event_scan(
        _state: ServerState,
        backend: ServerBackend,
        caller: Caller,
        bytes: Bytes,
    ) -> Result<(HeaderMap, Vec<u8>)> {
        let account = {
            let reader = backend.read().await;
            let accounts = reader.accounts();
            let reader = accounts.read().await;
            let account = reader
                .get(caller.address())
                .ok_or_else(|| Error::NoAccount(*caller.address()))?;
            Arc::clone(account)
        };

        let req = ScanRequest::decode(bytes).await?;

        // Maximum number of proofs to return in a single request
        if req.limit > 256 {
            return Err(Error::BadRequest);
        }

        let reader = account.read().await;
        let response =
            server_helpers::event_scan(&req, &reader.storage).await?;

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_PROTOBUF),
        );

        Ok((headers, response.encode().await?))
    }

    pub(super) async fn event_diff(
        _state: ServerState,
        backend: ServerBackend,
        caller: Caller,
        bytes: Bytes,
    ) -> Result<(HeaderMap, Vec<u8>)> {
        let account = {
            let reader = backend.read().await;
            let accounts = reader.accounts();
            let reader = accounts.read().await;
            let account = reader
                .get(caller.address())
                .ok_or_else(|| Error::NoAccount(*caller.address()))?;
            Arc::clone(account)
        };

        let req = DiffRequest::decode(bytes).await?;

        let reader = account.read().await;
        let response =
            server_helpers::event_diff(&req, &reader.storage).await?;

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_PROTOBUF),
        );

        Ok((headers, response.encode().await?))
    }

    pub(super) async fn event_patch(
        state: ServerState,
        backend: ServerBackend,
        caller: Caller,
        bytes: Bytes,
    ) -> Result<(HeaderMap, Vec<u8>)> {
        let account = {
            let reader = backend.read().await;
            let accounts = reader.accounts();
            let reader = accounts.read().await;
            let account = reader
                .get(caller.address())
                .ok_or_else(|| Error::NoAccount(*caller.address()))?;
            Arc::clone(account)
        };

        let req = PatchRequest::decode(bytes).await?;

        let (response, outcome) = {
            let mut writer = account.write().await;
            server_helpers::event_patch(req, &mut writer.storage).await?
        };

        #[cfg(feature = "listen")]
        if outcome.changes > 0 {
            if let Some(conn_id) = caller.connection_id() {
                let reader = account.read().await;
                let local_status = reader.storage.sync_status().await?;
                let notification = ChangeNotification::new(
                    caller.address(),
                    conn_id.to_string(),
                    local_status.root,
                    outcome,
                );
                let reader = state.read().await;
                send_notification(&*reader, &caller, notification).await;
            }
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_PROTOBUF),
        );

        Ok((headers, response.encode().await?))
    }

    pub(super) async fn sync_account(
        state: ServerState,
        backend: ServerBackend,
        caller: Caller,
        bytes: Bytes,
    ) -> Result<(HeaderMap, Vec<u8>)> {
        let account = {
            let reader = backend.read().await;
            let accounts = reader.accounts();
            let reader = accounts.read().await;
            let account = reader
                .get(caller.address())
                .ok_or_else(|| Error::NoAccount(*caller.address()))?;
            Arc::clone(account)
        };

        let packet = SyncPacket::decode(bytes).await?;

        let (packet, outcome) = {
            let mut writer = account.write().await;
            server_helpers::sync_account(packet, &mut writer.storage).await?
        };

        #[cfg(feature = "listen")]
        if outcome.changes > 0 {
            if let Some(conn_id) = caller.connection_id() {
                let notification = ChangeNotification::new(
                    caller.address(),
                    conn_id.to_string(),
                    packet.status.root,
                    outcome,
                );
                let reader = state.read().await;
                send_notification(&*reader, &caller, notification).await;
            }
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_PROTOBUF),
        );

        Ok((headers, packet.encode().await?))
    }
}
