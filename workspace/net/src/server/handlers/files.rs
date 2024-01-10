use axum::{
    body::Bytes,
    extract::{BodyStream, Extension, Path, Query, TypedHeader},
    headers::{authorization::Bearer, Authorization, ContentLength},
    http::StatusCode,
    response::IntoResponse,
};
use futures::StreamExt;

//use axum_macros::debug_handler;

use crate::{
    sdk::{
        storage::files::ExternalFileName,
        vault::{secret::SecretId, VaultId},
    },
    server::{
        authenticate::{self, BearerToken},
        Error, Result, ServerBackend, ServerState,
    },
};
use serde::Deserialize;
use std::sync::Arc;
use tokio::{
    fs::File,
    io::{AsyncWriteExt, BufWriter},
};

// Handler for files.
pub(crate) struct FileHandler;
impl FileHandler {
    /// Handler that receives an external file.
    pub(crate) async fn receive_file(
        Extension(state): Extension<ServerState>,
        Extension(backend): Extension<ServerBackend>,
        TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
        TypedHeader(content_length): TypedHeader<ContentLength>,
        Path((vault_id, secret_id, file_name)): Path<(
            VaultId,
            SecretId,
            ExternalFileName,
        )>,
        body: BodyStream,
    ) -> impl IntoResponse {
        match authenticate_file_api(bearer, &vault_id, &secret_id, &file_name)
            .await
        {
            Ok(token) => {
                match receive_file(
                    state,
                    backend,
                    token,
                    vault_id,
                    secret_id,
                    file_name,
                    content_length.0,
                    body,
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

    /// Handler that deletes an external file.
    pub(crate) async fn delete_file(
        Extension(state): Extension<ServerState>,
        Extension(backend): Extension<ServerBackend>,
        TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
        Path((vault_id, secret_id, file_name)): Path<(
            VaultId,
            SecretId,
            ExternalFileName,
        )>,
    ) -> impl IntoResponse {
        match authenticate_file_api(bearer, &vault_id, &secret_id, &file_name)
            .await
        {
            Ok(token) => {
                match delete_file(
                    state,
                    backend,
                    token,
                    vault_id,
                    secret_id,
                    file_name,
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
}

// Parse the bearer token
async fn authenticate_file_api(
    bearer: Authorization<Bearer>,
    vault_id: &VaultId,
    secret_id: &SecretId,
    file_name: &ExternalFileName,
) -> Result<BearerToken> {
    let signed_data = format!("{}/{}/{}", vault_id, secret_id, file_name);
    let token = authenticate::bearer(bearer, signed_data.as_bytes())
        .await
        .map_err(|_| Error::BadRequest)?;
    Ok(token)
}

async fn receive_file(
    _state: ServerState,
    backend: ServerBackend,
    token: BearerToken,
    vault_id: VaultId,
    secret_id: SecretId,
    file_name: ExternalFileName,
    content_length: u64,
    mut body: BodyStream,
) -> Result<()> {
    let account = {
        let backend = backend.read().await;
        let accounts = backend.accounts();
        let accounts = accounts.read().await;
        let account = accounts
            .get(&token.address)
            .ok_or_else(|| Error::NoAccount(token.address))?;
        Arc::clone(account)
    };

    let file_path = {
        let reader = account.read().await;
        let paths = reader.storage.paths();
        let name = file_name.to_string();
        paths.file_location(&vault_id, &secret_id, &name)
    };

    // TODO: compute and verify checksum

    let mut bytes_written = 0;
    let file = File::create(&file_path).await?;
    let mut buf_writer = BufWriter::new(file);
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        bytes_written += buf_writer.write(&chunk).await?;
    }
    buf_writer.flush().await?;

    if bytes_written != content_length as usize {
        tokio::fs::remove_file(&file_path).await?;
        return Err(Error::ContentLengthMismatch(
            content_length as usize,
            bytes_written,
        ));
    }

    Ok(())
}

async fn delete_file(
    _state: ServerState,
    backend: ServerBackend,
    token: BearerToken,
    vault_id: VaultId,
    secret_id: SecretId,
    file_name: ExternalFileName,
) -> Result<()> {
    let account = {
        let backend = backend.read().await;
        let accounts = backend.accounts();
        let accounts = accounts.read().await;
        let account = accounts
            .get(&token.address)
            .ok_or_else(|| Error::NoAccount(token.address))?;
        Arc::clone(account)
    };

    let file_path = {
        let reader = account.read().await;
        let paths = reader.storage.paths();
        let name = file_name.to_string();
        paths.file_location(&vault_id, &secret_id, &name)
    };

    tokio::fs::remove_file(&file_path).await?;

    Ok(())
}
