use axum::{
    body::{to_bytes, Body},
    extract::{Extension, Path, Query, Request},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

use super::{authenticate_endpoint, Caller};
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

//use axum_macros::debug_handler;

use crate::{
    sdk::{
        storage::files::{ExternalFile, ExternalFileName},
        sync::SyncStorage,
        vault::{secret::SecretId, VaultId},
    },
    server::{
        authenticate::{self, BearerToken},
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

// Handler for accounts.
pub(crate) struct AccountHandler;
impl AccountHandler {
    /// Handler that creates an account.
    pub(crate) async fn create_account(
        Extension(state): Extension<ServerState>,
        Extension(backend): Extension<ServerBackend>,
        TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
        body: Body,
    ) -> impl IntoResponse {
        match to_bytes(body, usize::MAX).await {
            Ok(bytes) => match authenticate_endpoint(bearer, &bytes).await {
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
        request: Request,
    ) -> impl IntoResponse {
        let uri = request.uri().path().to_string();
        match authenticate_endpoint(bearer, uri.as_bytes()).await {
            Ok(caller) => match fetch_account(state, backend, caller).await {
                Ok(result) => result.into_response(),
                Err(error) => error.into_response(),
            },
            Err(error) => error.into_response(),
        }
    }

    /// Handler that gets account sync status.
    pub(crate) async fn sync_status(
        Extension(state): Extension<ServerState>,
        Extension(backend): Extension<ServerBackend>,
        TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
        request: Request,
    ) -> impl IntoResponse {
        let uri = request.uri().path().to_string();
        match authenticate_endpoint(bearer, uri.as_bytes()).await {
            Ok(caller) => match sync_status(state, backend, caller).await {
                Ok(result) => result.into_response(),
                Err(error) => error.into_response(),
            },
            Err(error) => error.into_response(),
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
