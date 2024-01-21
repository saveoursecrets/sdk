use axum::{
    body::Body,
    extract::{Extension, OriginalUri, Path, Query, Request},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    typed_header::TypedHeader,
};

//use axum_macros::debug_handler;

use crate::{
    sdk::{
        storage::files::{ExternalFile, ExternalFileName},
        vault::{secret::SecretId, VaultId},
    },
    server::{
        handlers::{authenticate_endpoint, ConnectionQuery},
        ServerBackend, ServerState, ServerTransfer,
    },
};
use serde::Deserialize;
use std::sync::Arc;

/// Query string for moving a file.
#[derive(Debug, Deserialize)]
pub struct MoveFileQuery {
    pub vault_id: VaultId,
    pub secret_id: SecretId,
    pub name: ExternalFileName,
}

/// Upload a file.
#[utoipa::path(
    put,
    path = "/sync/file/{vault_id}/{secret_id}/{file_name}",
    security(
        ("bearer_token" = [])
    ),
    request_body(
        content_type = "application/octet-stream",
        content = Vec<u8>,
    ),
    params(
        ("vault_id" = Uuid, description = "Vault identifier"),
        ("secret_id" = Uuid, description = "Secret identifier"),
        ("file_name" = ExternalFileName, description = "Hex-encoded SHA256 checksum"),
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
            description = "File was uploaded.",
        ),
    ),
)]
pub(crate) async fn receive_file(
    Extension(state): Extension<ServerState>,
    Extension(backend): Extension<ServerBackend>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    Path((vault_id, secret_id, file_name)): Path<(
        VaultId,
        SecretId,
        ExternalFileName,
    )>,
    Query(query): Query<ConnectionQuery>,
    OriginalUri(uri): OriginalUri,
    body: Body,
) -> impl IntoResponse {
    let uri = uri.path().to_string();
    match authenticate_endpoint(
        bearer,
        uri.as_bytes(),
        query,
        Arc::clone(&state),
        Arc::clone(&backend),
        true,
    )
    .await
    {
        Ok(caller) => {
            match handlers::receive_file(
                state, backend, caller, vault_id, secret_id, file_name, body,
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

/// Delete a file.
#[utoipa::path(
    delete,
    path = "/sync/file/{vault_id}/{secret_id}/{file_name}",
    security(
        ("bearer_token" = [])
    ),
    params(
        ("vault_id" = Uuid, description = "Vault identifier"),
        ("secret_id" = Uuid, description = "Secret identifier"),
        ("file_name" = ExternalFileName, description = "Hex-encoded SHA256 checksum"),
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
            description = "File was deleted.",
        ),
    ),
)]
pub(crate) async fn delete_file(
    Extension(state): Extension<ServerState>,
    Extension(backend): Extension<ServerBackend>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    Path((vault_id, secret_id, file_name)): Path<(
        VaultId,
        SecretId,
        ExternalFileName,
    )>,
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
        true,
    )
    .await
    {
        Ok(caller) => {
            match handlers::delete_file(
                state, backend, caller, vault_id, secret_id, file_name,
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

/// Download a file.
#[utoipa::path(
    get,
    path = "/sync/file/{vault_id}/{secret_id}/{file_name}",
    security(
        ("bearer_token" = [])
    ),
    params(
        ("vault_id" = Uuid, description = "Vault identifier"),
        ("secret_id" = Uuid, description = "Secret identifier"),
        ("file_name" = ExternalFileName, description = "Hex-encoded SHA256 checksum"),
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
            description = "File was sent.",
        ),
    ),
)]
pub(crate) async fn send_file(
    Extension(state): Extension<ServerState>,
    Extension(backend): Extension<ServerBackend>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    Path((vault_id, secret_id, file_name)): Path<(
        VaultId,
        SecretId,
        ExternalFileName,
    )>,
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
        true,
    )
    .await
    {
        Ok(caller) => {
            match handlers::send_file(
                state, backend, caller, vault_id, secret_id, file_name,
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

/// Move a file.
#[utoipa::path(
    post,
    path = "/sync/file/{vault_id}/{secret_id}/{file_name}",
    security(
        ("bearer_token" = [])
    ),
    params(
        ("vault_id" = Uuid, description = "Vault identifier"),
        ("secret_id" = Uuid, description = "Secret identifier"),
        ("file_name" = ExternalFileName, description = "Hex-encoded SHA256 checksum"),
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
            description = "File was moved.",
        ),
    ),
)]
pub(crate) async fn move_file(
    Extension(state): Extension<ServerState>,
    Extension(backend): Extension<ServerBackend>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    Path((vault_id, secret_id, file_name)): Path<(
        VaultId,
        SecretId,
        ExternalFileName,
    )>,
    Query(query): Query<ConnectionQuery>,
    Query(move_query): Query<MoveFileQuery>,
    OriginalUri(uri): OriginalUri,
) -> impl IntoResponse {
    let uri = uri.path().to_string();
    match authenticate_endpoint(
        bearer,
        uri.as_bytes(),
        query,
        Arc::clone(&state),
        Arc::clone(&backend),
        true,
    )
    .await
    {
        Ok(token) => {
            match handlers::move_file(
                state, backend, token, vault_id, secret_id, file_name,
                move_query,
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

mod handlers {

    use axum::{body::Body, http::StatusCode, response::Response};

    use futures::TryStreamExt;
    use sos_sdk::sha2::{Digest, Sha256};

    //use axum_macros::debug_handler;

    use crate::{
        sdk::{
            storage::files::ExternalFileName,
            vault::{secret::SecretId, VaultId},
        },
        server::{
            handlers::Caller, Error, Result, ServerBackend, ServerState,
        },
    };
    use http::header;
    use std::sync::Arc;
    use tokio::{
        fs::File,
        io::{AsyncWriteExt, BufWriter},
    };
    use tokio_util::io::ReaderStream;

    use super::MoveFileQuery;

    pub(super) async fn receive_file(
        _state: ServerState,
        backend: ServerBackend,
        caller: Caller,
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
                .get(caller.address())
                .ok_or_else(|| Error::NoAccount(*caller.address()))?;
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
            return Err(Error::Status(StatusCode::NOT_MODIFIED));
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

    pub(super) async fn delete_file(
        _state: ServerState,
        backend: ServerBackend,
        caller: Caller,
        vault_id: VaultId,
        secret_id: SecretId,
        file_name: ExternalFileName,
    ) -> Result<()> {
        let account = {
            let backend = backend.read().await;
            let accounts = backend.accounts();
            let accounts = accounts.read().await;
            let account = accounts
                .get(caller.address())
                .ok_or_else(|| Error::NoAccount(*caller.address()))?;
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

    pub(super) async fn send_file(
        _state: ServerState,
        backend: ServerBackend,
        caller: Caller,
        vault_id: VaultId,
        secret_id: SecretId,
        file_name: ExternalFileName,
    ) -> Result<Response> {
        let account = {
            let backend = backend.read().await;
            let accounts = backend.accounts();
            let accounts = accounts.read().await;
            let account = accounts
                .get(caller.address())
                .ok_or_else(|| Error::NoAccount(*caller.address()))?;
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
        Ok(Response::builder()
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(body)?)
    }

    pub(super) async fn move_file(
        _state: ServerState,
        backend: ServerBackend,
        caller: Caller,
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
                .get(caller.address())
                .ok_or_else(|| Error::NoAccount(*caller.address()))?;
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
