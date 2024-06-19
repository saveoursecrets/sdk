use axum::{
    body::{to_bytes, Body},
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

use super::BODY_LIMIT;
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
        Some(query),
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
        Some(query),
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
        Some(query),
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
        Some(query),
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

/// Compare file sets between the local state on disc
/// and the state of files on this server.
#[utoipa::path(
    post,
    path = "/sync/files",
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
            description = "File transfers set was created.",
        ),
    ),
)]
pub(crate) async fn compare_files(
    Extension(state): Extension<ServerState>,
    Extension(backend): Extension<ServerBackend>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    Query(query): Query<ConnectionQuery>,
    OriginalUri(uri): OriginalUri,
    body: Body,
) -> impl IntoResponse {
    let uri = uri.path().to_string();
    match to_bytes(body, BODY_LIMIT).await {
        Ok(bytes) => match authenticate_endpoint(
            bearer,
            uri.as_bytes(),
            Some(query),
            Arc::clone(&state),
            Arc::clone(&backend),
            true,
        )
        .await
        {
            Ok(token) => {
                match handlers::compare_files(state, backend, token, bytes)
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
    use super::MoveFileQuery;
    use crate::{
        protocol::{
            sync::{FileSet, FileTransfersSet},
            WireEncodeDecode,
        },
        sdk::{
            sha2::{Digest, Sha256},
            storage::files::{list_external_files, ExternalFileName},
            vault::{secret::SecretId, VaultId},
        },
        server::{
            handlers::Caller, Error, Result, ServerBackend, ServerState,
        },
    };
    use axum::{
        body::{Body, Bytes},
        http::StatusCode,
        response::Response,
    };
    use futures::TryStreamExt;
    use http::header::{self, HeaderMap, HeaderValue};
    use indexmap::IndexSet;
    use sos_sdk::constants::MIME_TYPE_PROTOBUF;
    use std::{path::PathBuf, sync::Arc};
    use tokio::{
        fs::File,
        io::{AsyncWriteExt, BufWriter},
    };
    use tokio_util::io::ReaderStream;

    // Receive guard deletes files that did not complete uploading.
    struct ReceiveGuard {
        file_path: PathBuf,
    }

    impl Drop for ReceiveGuard {
        fn drop(&mut self) {
            if self.file_path.exists() {
                let _ = std::fs::remove_file(&self.file_path);
            }
        }
    }

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

        let mut upload_path = file_path.clone();
        upload_path.set_extension("upload");

        let mut _guard = ReceiveGuard {
            file_path: upload_path.clone(),
        };

        if !tokio::fs::try_exists(&parent_path).await? {
            tokio::fs::create_dir_all(&parent_path).await?;
        }

        let file = File::create(&upload_path).await?;
        let mut buf_writer = BufWriter::new(file);
        let mut stream = body.into_data_stream();
        let mut hasher = Sha256::new();
        while let Some(chunk) = stream.try_next().await? {
            buf_writer.write_all(&chunk).await?;
            hasher.update(&chunk);
        }

        buf_writer.flush().await?;
        let digest = hasher.finalize();

        if digest.as_slice() != file_name.as_ref() {
            return Err(Error::FileChecksumMismatch(
                file_name.to_string(),
                hex::encode(digest.as_slice()),
            ));
        }

        // Move the upload into place
        tokio::fs::rename(upload_path, file_path).await?;

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

        let metadata = tokio::fs::metadata(&file_path).await?;
        let file = File::open(&file_path).await?;
        let stream = ReaderStream::new(file);

        let body = axum::body::Body::from_stream(stream);
        Ok(Response::builder()
            .header(header::CONTENT_LENGTH, metadata.len())
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

    pub(super) async fn compare_files(
        _state: ServerState,
        backend: ServerBackend,
        caller: Caller,
        body: Bytes,
    ) -> Result<(HeaderMap, Vec<u8>)> {
        let paths = {
            let backend = backend.read().await;
            let accounts = backend.accounts();
            let accounts = accounts.read().await;
            let account = accounts
                .get(caller.address())
                .ok_or_else(|| Error::NoAccount(*caller.address()))?;
            let account = account.read().await;
            account.storage.paths()
        };

        let local_files = FileSet::decode(body).await?;
        let local_set = local_files.0;
        let remote_set = list_external_files(&*paths).await?;
        let uploads = local_set
            .difference(&remote_set)
            .cloned()
            .collect::<IndexSet<_>>();
        let downloads = remote_set
            .difference(&local_set)
            .cloned()
            .collect::<IndexSet<_>>();
        let transfers = FileTransfersSet {
            uploads: FileSet(uploads),
            downloads: FileSet(downloads),
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_PROTOBUF),
        );

        Ok((headers, transfers.encode().await?))
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
