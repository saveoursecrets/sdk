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

use crate::{
    server::{
        handlers::ConnectionQuery, ServerBackend, ServerState,
    },
};
use std::sync::Arc;

// FIXME: sensible body limit
const BODY_LIMIT: usize = usize::MAX;

//body = ErrorMessage,

/// Create an account.
#[utoipa::path(
    post,
    path = "/sync/account",
    security(
        ("bearer_token" = [])
    ),
    responses(
        (
            status = StatusCode::UNAUTHORIZED,
            description = "Authorization failed.",
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
            query,
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
        query,
        Arc::clone(&state),
        Arc::clone(&backend),
        false,
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
    path = "/sync/account",
    security(
        ("bearer_token" = [])
    ),
    responses(
        (
            status = StatusCode::UNAUTHORIZED,
            description = "Authorization failed.",
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
            query,
            Arc::clone(&state),
            Arc::clone(&backend),
            false,
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
    // FIXME: this endpoint should be restricted!
    match authenticate_endpoint(
        bearer,
        uri.as_bytes(),
        query,
        Arc::clone(&state),
        Arc::clone(&backend),
        false,
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
    put,
    path = "/sync/account",
    security(
        ("bearer_token" = [])
    ),
    responses(
        (
            status = StatusCode::UNAUTHORIZED,
            description = "Authorization failed.",
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
            query,
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
        server::{
            Error, Result, ServerBackend,
            ServerState,
        },
    };
    use sos_sdk::{decode, encode, sync::ChangeSet};
    use std::sync::Arc;
    use tracing::{span, Level};

    #[cfg(feature = "listen")]
    use crate::{server::handlers::send_notification, ChangeNotification};

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

    pub(super) async fn fetch_account(
        _state: ServerState,
        backend: ServerBackend,
        caller: Caller,
    ) -> Result<Vec<u8>> {
        let reader = backend.read().await;
        let account: ChangeSet =
            reader.fetch_account(caller.address()).await?;
        Ok(encode(&account).await?)
    }

    pub(super) async fn sync_status(
        _state: ServerState,
        backend: ServerBackend,
        caller: Caller,
    ) -> Result<Vec<u8>> {
        let account_exists = {
            let reader = backend.read().await;
            reader.account_exists(caller.address()).await?
        };
        let result = if account_exists {
            let reader = backend.read().await;
            let accounts = reader.accounts();
            let reader = accounts.read().await;
            let account = reader.get(caller.address()).unwrap();
            let account = account.read().await;
            let status = account.storage.sync_status().await?;
            Some(status)
        } else {
            None
        };
        Ok(serde_json::to_vec(&result)?)
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
    ) -> Result<Vec<u8>> {
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
        let num_changes = {
            let span = span!(Level::DEBUG, "merge_server");
            let _enter = span.enter();
            let mut writer = account.write().await;
            writer.storage.merge(&diff).await?
        };

        // Generate a new diff so the client can apply changes
        // that exist in remote but not in the local
        let (local_status, diff) = {
            let reader = account.read().await;
            let (_, local_status, diff) =
                sync::diff(&reader.storage, remote_status).await?;
            (local_status, diff)
        };

        #[cfg(feature = "listen")]
        if num_changes > 0 {
            let notification = ChangeNotification::new(caller.address());
            let mut writer = state.write().await;
            send_notification(&mut *writer, &caller, notification);
        }

        let packet = SyncPacket {
            status: local_status,
            diff,
        };

        Ok(encode(&packet).await?)
    }
}
