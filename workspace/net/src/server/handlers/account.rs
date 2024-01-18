use axum::{
    body::{Body, to_bytes},
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
use sos_sdk::{sha2::{Digest, Sha256}, decode, sync::ChangeSet};
use super::{authenticate_endpoint, Caller};

//use axum_macros::debug_handler;

use crate::{
    sdk::{
        storage::files::{ExternalFile, ExternalFileName},
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
            Ok(bytes) => {
                match authenticate_endpoint(bearer, &bytes)
                    .await
                {
                    Ok(caller) => {
                        match create_account(
                            state, backend, caller, &bytes,
                        )
                        .await
                        {
                            Ok(result) => result.into_response(),
                            Err(error) => error.into_response(),
                        }
                    }
                    Err(error) => error.into_response(),
                }
            }
            Err(e) => {
                StatusCode::BAD_REQUEST.into_response()
            }
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
