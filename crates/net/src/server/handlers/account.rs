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
use crate::server::{handlers::ConnectionQuery, ServerBackend, ServerState};
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
        content_type = "application/octet-stream",
        content = ChangeSet,
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
                match handlers::create_account(state, backend, caller, &bytes)
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
        content_type = "application/octet-stream",
        content = ChangeSet,
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
            description = "Account was created.",
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
                match handlers::update_account(state, backend, caller, &bytes)
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
            description = "Account data sent.",
            body = ChangeSet,
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

/// Patch device event log.
#[utoipa::path(
    patch,
    path = "/sync/account/devices",
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
            description = "Patch was applied to device event log.",
        ),
    ),
)]
#[cfg(feature = "device")]
pub(crate) async fn patch_devices(
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
                match handlers::patch_devices(state, backend, caller, &bytes)
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
            description = "Account sync status sent.",
            body = SyncStatus,
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

/// Sync account event logs.
#[utoipa::path(
    patch,
    path = "/sync/account",
    security(
        ("bearer_token" = [])
    ),
    request_body(
        content_type = "application/octet-stream",
        content = SyncPacket,
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
            description = "Account event logs were patched.",
            body = SyncPacket,
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
                match handlers::sync_account(state, backend, caller, &bytes)
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
    use crate::{
        sdk::sync::{self, Merge, SyncPacket, SyncStorage},
        server::{Error, Result, ServerBackend, ServerState},
    };
    use http::{
        header::{self, HeaderMap, HeaderValue},
        StatusCode,
    };
    use sos_sdk::{
        constants::MIME_TYPE_SOS,
        decode, encode,
        sync::{ChangeSet, UpdateSet},
    };
    use std::sync::Arc;

    #[cfg(feature = "listen")]
    use crate::{server::handlers::send_notification, ChangeNotification};

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
        bytes: &[u8],
    ) -> Result<()> {
        {
            let reader = backend.read().await;
            if reader.account_exists(caller.address()).await? {
                return Err(Error::Conflict);
            }
        }

        let account: ChangeSet = decode(bytes).await?;
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
        bytes: &[u8],
    ) -> Result<()> {
        let account: UpdateSet = decode(bytes).await?;
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
        let account: ChangeSet =
            reader.fetch_account(caller.address()).await?;

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_SOS),
        );

        Ok((headers, encode(&account).await?))
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
        let encoded = encode(&status).await?;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_SOS),
        );

        Ok((headers, encoded))
    }

    #[cfg(feature = "device")]
    pub(super) async fn patch_devices(
        _state: ServerState,
        backend: ServerBackend,
        caller: Caller,
        bytes: &[u8],
    ) -> Result<()> {
        use crate::sdk::sync::DeviceDiff;
        let diff: DeviceDiff = decode(bytes).await?;
        let reader = backend.read().await;
        reader.patch_devices(caller.address(), &diff).await?;
        Ok(())
    }

    pub(super) async fn sync_account(
        state: ServerState,
        backend: ServerBackend,
        caller: Caller,
        bytes: &[u8],
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

        let packet: SyncPacket = decode(bytes).await?;
        let (remote_status, diff) = (packet.status, packet.diff);

        // Apply the diff to the storage
        let (outcome, compare) = {
            tracing::debug!("merge_server");
            let mut writer = account.write().await;
            writer.storage.merge(&diff).await?
        };

        println!("outcome: {:#?}", outcome);
        println!("compare: {:#?}", compare);
        // println!("diff: {:#?}", diff);

        // Generate a new diff so the client can apply changes
        // that exist in remote but not in the local
        let (local_status, diff) = {
            let reader = account.read().await;
            let (_, local_status, diff) =
                sync::diff(&reader.storage, remote_status).await?;
            (local_status, diff)
        };

        #[cfg(feature = "listen")]
        if outcome.changes > 0 {
            if let Some(conn_id) = caller.connection_id() {
                let notification = ChangeNotification::new(
                    caller.address(),
                    conn_id.to_string(),
                    local_status.root,
                    outcome,
                );
                let mut writer = state.write().await;
                send_notification(&mut *writer, &caller, notification).await;
            }
        }

        let packet = SyncPacket {
            status: local_status,
            diff,
            compare: Some(compare),
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_SOS),
        );

        Ok((headers, encode(&packet).await?))
    }
}
