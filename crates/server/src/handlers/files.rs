use super::{parse_account_id, BODY_LIMIT};
use crate::{
    handlers::{authenticate_endpoint, ConnectionQuery},
    ServerBackend, ServerState, ServerTransfer,
};
use axum::{
    body::{to_bytes, Body},
    extract::{Extension, OriginalUri, Path, Query, Request},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    typed_header::TypedHeader,
};
use serde::Deserialize;
use sos_core::{
    ExternalFile, ExternalFileName, SecretId, SecretPath, VaultId,
};
use std::sync::Arc;

//use axum_macros::debug_handler;

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
        ("file_name" = String, description = "Hex-encoded SHA256 checksum"),
    ),
    responses(
        (
            status = StatusCode::UNAUTHORIZED,
            description = "Authorization failed.",
        ),
        (
            status = StatusCode::FORBIDDEN,
            description = "Account identifier is not allowed on this server.",
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
    headers: HeaderMap,
    body: Body,
) -> impl IntoResponse {
    let uri = uri.path().to_string();
    let account_id = parse_account_id(&headers);
    match authenticate_endpoint(
        account_id,
        bearer,
        uri.as_bytes(),
        Some(query),
        Arc::clone(&state),
        Arc::clone(&backend),
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
        ("file_name" = String, description = "Hex-encoded SHA256 checksum"),
    ),
    responses(
        (
            status = StatusCode::UNAUTHORIZED,
            description = "Authorization failed.",
        ),
        (
            status = StatusCode::FORBIDDEN,
            description = "Account identifier is not allowed on this server.",
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
    headers: HeaderMap,
) -> impl IntoResponse {
    let uri = uri.path().to_string();
    let account_id = parse_account_id(&headers);
    match authenticate_endpoint(
        account_id,
        bearer,
        uri.as_bytes(),
        Some(query),
        Arc::clone(&state),
        Arc::clone(&backend),
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
        ("file_name" = String, description = "Hex-encoded SHA256 checksum"),
    ),
    responses(
        (
            status = StatusCode::UNAUTHORIZED,
            description = "Authorization failed.",
        ),
        (
            status = StatusCode::FORBIDDEN,
            description = "Account identifier is not allowed on this server.",
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
    headers: HeaderMap,
) -> impl IntoResponse {
    let uri = uri.path().to_string();
    let account_id = parse_account_id(&headers);
    match authenticate_endpoint(
        account_id,
        bearer,
        uri.as_bytes(),
        Some(query),
        Arc::clone(&state),
        Arc::clone(&backend),
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
        ("file_name" = String, description = "Hex-encoded SHA256 checksum"),
    ),
    responses(
        (
            status = StatusCode::UNAUTHORIZED,
            description = "Authorization failed.",
        ),
        (
            status = StatusCode::FORBIDDEN,
            description = "Account identifier is not allowed on this server.",
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
    headers: HeaderMap,
) -> impl IntoResponse {
    let uri = uri.path().to_string();
    let account_id = parse_account_id(&headers);
    match authenticate_endpoint(
        account_id,
        bearer,
        uri.as_bytes(),
        Some(query),
        Arc::clone(&state),
        Arc::clone(&backend),
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
            description = "Account identifier is not allowed on this server.",
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
    headers: HeaderMap,
    body: Body,
) -> impl IntoResponse {
    let uri = uri.path().to_string();
    let account_id = parse_account_id(&headers);
    match to_bytes(body, BODY_LIMIT).await {
        Ok(bytes) => match authenticate_endpoint(
            account_id,
            bearer,
            uri.as_bytes(),
            Some(query),
            Arc::clone(&state),
            Arc::clone(&backend),
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
        handlers::Caller, Error, Result, ServerBackend, ServerState,
    };
    use axum::{
        body::{Body, Bytes},
        http::StatusCode,
        response::Response,
    };
    use futures::TryStreamExt;
    use http::header::{self, HeaderMap, HeaderValue};
    use indexmap::IndexSet;
    use sha2::{Digest, Sha256};
    use sos_core::{ExternalFileName, SecretId, VaultId};
    use sos_external_files::list_external_files;
    use sos_protocol::{
        constants::MIME_TYPE_PROTOBUF,
        transfer::{FileSet, FileTransfersSet},
        WireEncodeDecode,
    };
    use sos_server_storage::ServerAccountStorage;
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
                .get(caller.account_id())
                .ok_or_else(|| Error::NoAccount(*caller.account_id()))?;
            Arc::clone(account)
        };

        let (parent_path, file_path) = {
            let reader = account.read().await;
            let paths = reader.paths();
            let parent_path =
                paths.into_file_secret_path(&vault_id, &secret_id);

            (
                parent_path,
                paths.into_file_path_parts(&vault_id, &secret_id, &file_name),
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
                .get(caller.account_id())
                .ok_or_else(|| Error::NoAccount(*caller.account_id()))?;
            Arc::clone(account)
        };

        let file_path = {
            let reader = account.read().await;
            let paths = reader.paths();
            paths.into_file_path_parts(&vault_id, &secret_id, &file_name)
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
                .get(caller.account_id())
                .ok_or_else(|| Error::NoAccount(*caller.account_id()))?;
            Arc::clone(account)
        };

        let file_path = {
            let reader = account.read().await;
            let paths = reader.paths();
            paths.into_file_path_parts(&vault_id, &secret_id, &file_name)
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
                .get(caller.account_id())
                .ok_or_else(|| Error::NoAccount(*caller.account_id()))?;
            Arc::clone(account)
        };

        let (source_path, target_path, parent_path) = {
            let reader = account.read().await;
            let paths = reader.paths();
            let source =
                paths.into_file_path_parts(&vault_id, &secret_id, &file_name);
            let target = paths.into_file_path_parts(
                &query.vault_id,
                &query.secret_id,
                &query.name,
            );
            let parent_path = paths
                .into_file_secret_path(&query.vault_id, &query.secret_id);

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
                .get(caller.account_id())
                .ok_or_else(|| Error::NoAccount(*caller.account_id()))?;
            let account = account.read().await;
            account.paths()
        };

        let local_files = FileSet::decode(body).await?;
        let local_set = local_files.0;
        tracing::debug!(
            local_set_len = %local_set.len(), "compare_files");

        let remote_set = list_external_files(&*paths).await?;
        tracing::debug!(
            remote_set_len = %remote_set.len(), "compare_files");

        let uploads = local_set
            .difference(&remote_set)
            .cloned()
            .collect::<IndexSet<_>>();
        let downloads = remote_set
            .difference(&local_set)
            .cloned()
            .collect::<IndexSet<_>>();

        tracing::debug!(
            uploads_len = %uploads.len(),
            downloads_len = %downloads.len(),
            "compare_files",
        );

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
    let file_ref =
        ExternalFile::new(SecretPath(vault_id, secret_id), file_name);
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
