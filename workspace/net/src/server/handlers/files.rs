use axum::{
    body::Body,
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
use sos_sdk::sha2::{Digest, Sha256};

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

/// Query string for moving a file.
#[derive(Debug, Deserialize)]
pub struct MoveFileQuery {
    pub vault_id: VaultId,
    pub secret_id: SecretId,
    pub name: ExternalFileName,
}

// Handler for files.
pub(crate) struct FileHandler;
impl FileHandler {
    /// Handler that receives an external file.
    pub(crate) async fn receive_file(
        Extension(state): Extension<ServerState>,
        Extension(backend): Extension<ServerBackend>,
        TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
        Path((vault_id, secret_id, file_name)): Path<(
            VaultId,
            SecretId,
            ExternalFileName,
        )>,
        body: Body,
    ) -> impl IntoResponse {
        match authenticate_file_api(bearer, &vault_id, &secret_id, &file_name)
            .await
        {
            Ok(token) => {
                match receive_file(
                    state, backend, token, vault_id, secret_id, file_name,
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
                    state, backend, token, vault_id, secret_id, file_name,
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

    /// Handler that sends an external file.
    pub(crate) async fn send_file(
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
                match send_file(
                    state, backend, token, vault_id, secret_id, file_name,
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

    /// Handler that moves an external file.
    pub(crate) async fn move_file(
        Extension(state): Extension<ServerState>,
        Extension(backend): Extension<ServerBackend>,
        TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
        Path((vault_id, secret_id, file_name)): Path<(
            VaultId,
            SecretId,
            ExternalFileName,
        )>,
        Query(query): Query<MoveFileQuery>,
    ) -> impl IntoResponse {
        match authenticate_file_api(bearer, &vault_id, &secret_id, &file_name)
            .await
        {
            Ok(token) => {
                match move_file(
                    state, backend, token, vault_id, secret_id, file_name,
                    query,
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
    body: Body,
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

    let (parent_path, file_path) = {
        let reader = account.read().await;
        let paths = reader.storage.paths();
        let name = file_name.to_string();
        let parent_path = paths
            .file_folder_location(&vault_id)
            .join(secret_id.to_string());
        (
            parent_path,
            paths.file_location(&vault_id, &secret_id, &name),
        )
    };

    if tokio::fs::try_exists(&file_path).await? {
        return Err(Error::Status(StatusCode::CONFLICT));
    }

    if !tokio::fs::try_exists(&parent_path).await? {
        tokio::fs::create_dir_all(&parent_path).await?;
    }

    let mut hasher = Sha256::new();
    let file = File::create(&file_path).await?;
    let mut buf_writer = BufWriter::new(file);
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.try_next().await? {
        buf_writer.write(&chunk).await?;
        hasher.update(&chunk);
    }

    buf_writer.flush().await?;
    let digest = hasher.finalize();

    if digest.as_slice() != file_name.as_ref() {
        tokio::fs::remove_file(&file_path).await?;
        return Err(Error::FileChecksumMismatch(
            file_name.to_string(),
            hex::encode(digest.as_slice()),
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

    if !tokio::fs::try_exists(&file_path).await? {
        return Err(Error::Status(StatusCode::NOT_FOUND));
    }

    tokio::fs::remove_file(&file_path).await?;

    Ok(())
}

async fn send_file(
    _state: ServerState,
    backend: ServerBackend,
    token: BearerToken,
    vault_id: VaultId,
    secret_id: SecretId,
    file_name: ExternalFileName,
) -> Result<Response> {
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

    if !tokio::fs::try_exists(&file_path).await? {
        return Err(Error::Status(StatusCode::NOT_FOUND));
    }

    let file = File::open(&file_path).await?;
    let stream = ReaderStream::new(file);

    let body = axum::body::Body::from_stream(stream);
    Ok(Response::builder().body(body)?)
}

async fn move_file(
    _state: ServerState,
    backend: ServerBackend,
    token: BearerToken,
    vault_id: VaultId,
    secret_id: SecretId,
    file_name: ExternalFileName,
    query: MoveFileQuery,
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

    let (source_path, target_path, parent_path) = {
        let reader = account.read().await;
        let paths = reader.storage.paths();
        let name = file_name.to_string();
        let source = paths.file_location(&vault_id, &secret_id, &name);
        let target = paths.file_location(
            &query.vault_id,
            &query.secret_id,
            &query.name.to_string(),
        );
        let parent_path = paths
            .file_folder_location(&query.vault_id)
            .join(query.secret_id.to_string());

        (source, target, parent_path)
    };

    if !tokio::fs::try_exists(&source_path).await? {
        return Err(Error::Status(StatusCode::NOT_FOUND));
    }

    if tokio::fs::try_exists(&target_path).await? {
        return Err(Error::Status(StatusCode::CONFLICT));
    }

    if !tokio::fs::try_exists(&parent_path).await? {
        tokio::fs::create_dir_all(&parent_path).await?;
    }

    {
        let mut source = File::open(&source_path).await?;
        let mut target = File::create(&target_path).await?;
        tokio::io::copy(&mut source, &mut target).await?;
    }
    tokio::fs::remove_file(&source_path).await?;

    Ok(())
}

/// Middleware to lock file operations so that concurrent
/// operations on an external file reference are not possible.
pub async fn file_operation_lock(
    Extension(transfer): Extension<ServerTransfer>,
    Path((vault_id, secret_id, file_name)): Path<(
        VaultId,
        SecretId,
        ExternalFileName,
    )>,
    request: Request,
    next: Next,
) -> Response {
    let file_ref = ExternalFile::new(vault_id, secret_id, file_name);
    {
        let mut writer = transfer.write().await;
        if writer.get(&file_ref).is_some() {
            return StatusCode::CONFLICT.into_response();
        }
        writer.insert(file_ref);
    }

    let response = next.run(request).await;

    {
        let mut writer = transfer.write().await;
        writer.remove(&file_ref);
    }

    response
}
