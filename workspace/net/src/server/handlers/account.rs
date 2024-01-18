use super::{authenticate_endpoint, Caller};
use axum::{
    body::{to_bytes, Body},
    extract::{Extension, Path, Query, Request},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    typed_header::TypedHeader,
};
use futures::TryStreamExt;
use sos_sdk::{
    decode, encode,
    sha2::{Digest, Sha256},
    sync::ChangeSet,
};
use tracing::{span, Level};

//use axum_macros::debug_handler;

use crate::{
    sdk::{
        storage::files::{ExternalFile, ExternalFileName},
        sync::{self, Merge, SyncPacket, SyncStorage},
        vault::{secret::SecretId, VaultId},
    },
    server::{
        authenticate::{self, BearerToken},
        handlers::ConnectionQuery,
        Error, Result, ServerBackend, ServerState, ServerTransfer,
    },
};
use serde::Deserialize;
use std::sync::Arc;
use tokio::{
    fs::File,
    io::{AsyncWriteExt, BufWriter},
};
use tokio_util::io::ReaderStream;

#[cfg(feature = "listen")]
use crate::events::ChangeNotification;

#[cfg(feature = "listen")]
use super::send_notification;

// FIXME: sensible body limit
const BODY_LIMIT: usize = usize::MAX;

// Handler for accounts.
pub(crate) struct AccountHandler;
impl AccountHandler {
    /// Handler that creates an account.
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
                    match create_account(state, backend, caller, &bytes).await
                    {
                        Ok(result) => result.into_response(),
                        Err(error) => error.into_response(),
                    }
                }
                Err(error) => error.into_response(),
            },
            Err(e) => StatusCode::BAD_REQUEST.into_response(),
        }
    }

    /// Handler that fetches an account.
    pub(crate) async fn fetch_account(
        Extension(state): Extension<ServerState>,
        Extension(backend): Extension<ServerBackend>,
        TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
        Query(query): Query<ConnectionQuery>,
        request: Request,
    ) -> impl IntoResponse {
        let uri = request.uri().path().to_string();
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
            Ok(caller) => match fetch_account(state, backend, caller).await {
                Ok(result) => result.into_response(),
                Err(error) => error.into_response(),
            },
            Err(error) => error.into_response(),
        }
    }

    /// Handler that patches device events.
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
                    match patch_devices(state, backend, caller, &bytes).await
                    {
                        Ok(result) => result.into_response(),
                        Err(error) => error.into_response(),
                    }
                }
                Err(error) => error.into_response(),
            },
            Err(e) => StatusCode::BAD_REQUEST.into_response(),
        }
    }

    /// Handler that gets account sync status.
    pub(crate) async fn sync_status(
        Extension(state): Extension<ServerState>,
        Extension(backend): Extension<ServerBackend>,
        TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
        Query(query): Query<ConnectionQuery>,
        request: Request,
    ) -> impl IntoResponse {
        let uri = request.uri().path().to_string();
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
            Ok(caller) => match sync_status(state, backend, caller).await {
                Ok(result) => result.into_response(),
                Err(error) => error.into_response(),
            },
            Err(error) => error.into_response(),
        }
    }

    /// Handler that syncs account events.
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
                    match sync_account(state, backend, caller, &bytes).await {
                        Ok(result) => result.into_response(),
                        Err(error) => error.into_response(),
                    }
                }
                Err(error) => error.into_response(),
            },
            Err(e) => StatusCode::BAD_REQUEST.into_response(),
        }
    }
}

async fn create_account(
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

async fn fetch_account(
    _state: ServerState,
    backend: ServerBackend,
    caller: Caller,
) -> Result<Vec<u8>> {
    let reader = backend.read().await;
    let account: ChangeSet = reader.fetch_account(caller.address()).await?;
    Ok(encode(&account).await?)
}

async fn sync_status(
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
async fn patch_devices(
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

async fn sync_account(
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
