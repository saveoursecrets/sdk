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
use crate::{handlers::ConnectionQuery, ServerBackend, ServerState};

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
        content = CreateSet,
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
                match handlers::create_account(state, backend, caller, bytes)
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
        content = CreateSet,
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
                match handlers::update_account(state, backend, caller, bytes)
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
            body = CreateSet,
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

/// Scan account event logs for commit proofs.
#[utoipa::path(
    get,
    path = "/sync/account/events",
    security(
        ("bearer_token" = [])
    ),
    request_body(
        content_type = "application/octet-stream",
        content = ScanRequest,
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
            description = "Commit hashes sent.",
            body = ScanResponse,
        ),
    ),
)]
pub(crate) async fn event_proofs(
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
                match handlers::event_proofs(state, backend, caller, bytes)
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

/// Fetch a diff from an event log.
#[utoipa::path(
    post,
    path = "/sync/account/events",
    security(
        ("bearer_token" = [])
    ),
    request_body(
        content_type = "application/octet-stream",
        content = DiffRequest,
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
            description = "Commit diff sent.",
            body = DiffResponse,
        ),
    ),
)]
pub(crate) async fn event_diff(
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
                match handlers::event_diff(state, backend, caller, bytes)
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

/// Patch an event log.
#[utoipa::path(
    patch,
    path = "/sync/account/events",
    security(
        ("bearer_token" = [])
    ),
    request_body(
        content_type = "application/octet-stream",
        content = PatchRequest,
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
            description = "Result of the attempt to apply the checked patch.",
            body = PatchResponse,
        ),
    ),
)]
pub(crate) async fn event_patch(
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
                match handlers::event_patch(state, backend, caller, bytes)
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
                match handlers::sync_account(state, backend, caller, bytes)
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
        backend::AccountStorage, Error, Result, ServerBackend, ServerState,
    };
    use axum::body::Bytes;
    use binary_stream::futures::{Decodable, Encodable};
    use http::{
        header::{self, HeaderMap, HeaderValue},
        StatusCode,
    };
    use sos_protocol::{
        sdk::{
            constants::MIME_TYPE_PROTOBUF,
            events::{
                AccountDiff, AccountEvent, CheckedPatch, DiscEventLog,
                EventLogExt, EventRecord, FolderDiff, Patch, WriteEvent,
            },
            storage::StorageEventLogs,
        },
        CreateSet, DiffRequest, DiffResponse, EventLogType, Merge,
        MergeOutcome, PatchRequest, PatchResponse, ScanRequest, ScanResponse,
        SyncPacket, SyncStorage, UpdateSet, WireEncodeDecode,
    };

    use tokio::sync::RwLock;

    use std::sync::Arc;

    #[cfg(feature = "files")]
    use sos_protocol::sdk::events::{FileDiff, FileEvent};

    use sos_protocol::sdk::events::{DeviceDiff, DeviceEvent};

    #[cfg(feature = "listen")]
    use sos_protocol::ChangeNotification;

    #[cfg(feature = "listen")]
    use crate::handlers::send_notification;

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
        bytes: Bytes,
    ) -> Result<()> {
        {
            let reader = backend.read().await;
            if reader.account_exists(caller.address()).await? {
                return Err(Error::Conflict);
            }
        }

        let account = CreateSet::decode(bytes).await?;
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
        bytes: Bytes,
    ) -> Result<()> {
        let account = UpdateSet::decode(bytes).await?;
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
        let account: CreateSet =
            reader.fetch_account(caller.address()).await?;

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_PROTOBUF),
        );

        Ok((headers, account.encode().await?))
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
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_PROTOBUF),
        );
        Ok((headers, status.encode().await?))
    }

    pub(super) async fn event_proofs(
        _state: ServerState,
        backend: ServerBackend,
        caller: Caller,
        bytes: Bytes,
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

        let req = ScanRequest::decode(bytes).await?;

        // Maximum number of proofs to return in a single request
        if req.limit > 256 {
            return Err(Error::BadRequest);
        }

        let response = match &req.log_type {
            EventLogType::Identity => {
                let reader = account.read().await;
                let log = reader.storage.identity_log();
                let event_log = log.read().await;
                scan_log(&req, &*event_log).await?
            }
            EventLogType::Account => {
                let reader = account.read().await;
                let log = reader.storage.account_log();
                let event_log = log.read().await;
                scan_log(&req, &*event_log).await?
            }
            EventLogType::Device => {
                let reader = account.read().await;
                let log = reader.storage.device_log().await?;
                let event_log = log.read().await;
                scan_log(&req, &*event_log).await?
            }
            #[cfg(feature = "files")]
            EventLogType::Files => {
                let reader = account.read().await;
                let log = reader.storage.file_log().await?;
                let event_log = log.read().await;
                scan_log(&req, &*event_log).await?
            }
            EventLogType::Folder(id) => {
                let reader = account.read().await;
                let log = reader.storage.folder_log(&id).await?;
                let event_log = log.read().await;
                scan_log(&req, &*event_log).await?
            }
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_PROTOBUF),
        );

        Ok((headers, response.encode().await?))
    }

    async fn scan_log<T>(
        req: &ScanRequest,
        event_log: &DiscEventLog<T>,
    ) -> Result<ScanResponse>
    where
        T: Default + Encodable + Decodable + Send + Sync + 'static,
    {
        let mut res = ScanResponse {
            first_proof: None,
            proofs: vec![],
            offset: 0,
        };
        let offset = req.offset;
        let num_commits = event_log.tree().len() as u64;

        let mut index = if event_log.tree().len() > 0 {
            event_log.tree().len() - 1
        } else {
            0
        };

        if event_log.tree().len() > 0 {
            res.first_proof = Some(event_log.tree().proof(&[0])?);
        }

        // Short circuit if the offset is clearly out of bounds
        if offset >= num_commits {
            res.offset = num_commits;
            return Ok(res);
        }

        let mut it = event_log.iter(true).await?;
        let mut skip = 0;

        loop {
            let event = it.next().await?;
            if offset > 0 && skip < offset {
                if index > 0 {
                    index -= 1;
                }
                skip += 1;
                continue;
            }
            if let Some(_event) = event {
                let proof = event_log.tree().proof(&[index])?;
                res.proofs.insert(0, proof);
                res.offset = offset + res.proofs.len() as u64;

                if index > 0 {
                    index -= 1;
                }

                if res.proofs.len() == req.limit as usize {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(res)
    }

    pub(super) async fn event_diff(
        _state: ServerState,
        backend: ServerBackend,
        caller: Caller,
        bytes: Bytes,
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

        let req = DiffRequest::decode(bytes).await?;

        let response = match &req.log_type {
            EventLogType::Identity => {
                let reader = account.read().await;
                let log = reader.storage.identity_log();
                let event_log = log.read().await;
                diff_log(&req, &*event_log).await?
            }
            EventLogType::Account => {
                let reader = account.read().await;
                let log = reader.storage.account_log();
                let event_log = log.read().await;
                diff_log(&req, &*event_log).await?
            }
            EventLogType::Device => {
                let reader = account.read().await;
                let log = reader.storage.device_log().await?;
                let event_log = log.read().await;
                diff_log(&req, &*event_log).await?
            }
            #[cfg(feature = "files")]
            EventLogType::Files => {
                let reader = account.read().await;
                let log = reader.storage.file_log().await?;
                let event_log = log.read().await;
                diff_log(&req, &*event_log).await?
            }
            EventLogType::Folder(id) => {
                let reader = account.read().await;
                let log = reader.storage.folder_log(id).await?;
                let event_log = log.read().await;
                diff_log(&req, &*event_log).await?
            }
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_PROTOBUF),
        );

        Ok((headers, response))
    }

    async fn diff_log<T>(
        req: &DiffRequest,
        event_log: &DiscEventLog<T>,
    ) -> Result<Vec<u8>>
    where
        T: Default + Encodable + Decodable + Send + Sync + 'static,
    {
        let response = DiffResponse {
            patch: event_log.diff_records(req.from_hash.as_ref()).await?,
            checkpoint: event_log.tree().head()?,
        };
        Ok(response.encode().await?)
    }

    pub(super) async fn event_patch(
        state: ServerState,
        backend: ServerBackend,
        caller: Caller,
        bytes: Bytes,
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

        let req = PatchRequest::decode(bytes).await?;

        let (checked_patch, outcome, records) = match &req.log_type {
            EventLogType::Identity => {
                let patch = Patch::<WriteEvent>::new(req.patch);
                let mut writer = account.write().await;
                let (last_commit, records) = if let Some(commit) = &req.commit
                {
                    let log = writer.storage.identity_log();
                    let mut event_log = log.write().await;
                    let records = event_log.rewind(commit).await?;
                    (Some(*commit), records)
                } else {
                    (None, vec![])
                };

                let diff = FolderDiff {
                    last_commit,
                    checkpoint: req.proof,
                    patch,
                };

                let mut outcome = MergeOutcome::default();
                (
                    writer.storage.merge_identity(diff, &mut outcome).await?,
                    outcome,
                    records,
                )
            }
            EventLogType::Account => {
                let patch = Patch::<AccountEvent>::new(req.patch);
                let mut writer = account.write().await;
                let (last_commit, records) = if let Some(commit) = &req.commit
                {
                    let log = writer.storage.account_log();
                    let mut event_log = log.write().await;
                    let records = event_log.rewind(commit).await?;
                    (Some(*commit), records)
                } else {
                    (None, vec![])
                };

                let diff = AccountDiff {
                    last_commit,
                    checkpoint: req.proof,
                    patch,
                };

                let mut outcome = MergeOutcome::default();
                (
                    writer.storage.merge_account(diff, &mut outcome).await?,
                    outcome,
                    records,
                )
            }
            EventLogType::Device => {
                let patch = Patch::<DeviceEvent>::new(req.patch);
                let mut writer = account.write().await;
                let (last_commit, records) = if let Some(commit) = &req.commit
                {
                    let log = writer.storage.device_log().await?;
                    let mut event_log = log.write().await;
                    let records = event_log.rewind(commit).await?;
                    (Some(*commit), records)
                } else {
                    (None, vec![])
                };

                let diff = DeviceDiff {
                    last_commit,
                    checkpoint: req.proof,
                    patch,
                };

                let mut outcome = MergeOutcome::default();
                (
                    writer.storage.merge_device(diff, &mut outcome).await?,
                    outcome,
                    records,
                )
            }
            #[cfg(feature = "files")]
            EventLogType::Files => {
                let patch = Patch::<FileEvent>::new(req.patch);
                let mut writer = account.write().await;
                let (last_commit, records) = if let Some(commit) = &req.commit
                {
                    let log = writer.storage.file_log().await?;
                    let mut event_log = log.write().await;
                    let records = event_log.rewind(commit).await?;
                    (Some(*commit), records)
                } else {
                    (None, vec![])
                };

                let diff = FileDiff {
                    last_commit,
                    checkpoint: req.proof,
                    patch,
                };

                let mut outcome = MergeOutcome::default();
                (
                    writer.storage.merge_files(diff, &mut outcome).await?,
                    outcome,
                    records,
                )
            }
            EventLogType::Folder(id) => {
                let patch = Patch::<WriteEvent>::new(req.patch);
                let mut writer = account.write().await;
                let (last_commit, records) = if let Some(commit) = &req.commit
                {
                    let log = writer.storage.folder_log(&id).await?;
                    let mut event_log = log.write().await;
                    let records = event_log.rewind(commit).await?;
                    (Some(*commit), records)
                } else {
                    (None, vec![])
                };

                let diff = FolderDiff {
                    last_commit,
                    checkpoint: req.proof,
                    patch,
                };

                let mut outcome = MergeOutcome::default();
                (
                    writer
                        .storage
                        .merge_folder(&id, diff, &mut outcome)
                        .await?,
                    outcome,
                    records,
                )
            }
        };

        #[cfg(feature = "listen")]
        if outcome.changes > 0 {
            if let Some(conn_id) = caller.connection_id() {
                let reader = account.read().await;
                let local_status = reader.storage.sync_status().await?;
                let notification = ChangeNotification::new(
                    caller.address(),
                    conn_id.to_string(),
                    local_status.root,
                    outcome,
                );
                let reader = state.read().await;
                send_notification(&*reader, &caller, notification).await;
            }
        }

        // Rollback the rewind if the merge failed
        if let CheckedPatch::Conflict { head, .. } = &checked_patch {
            tracing::warn!(
                head = ?head,
                num_records = ?records.len(),
                "events_patch::rollback_rewind");
            rollback_rewind(&req.log_type, account, records).await?;
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_PROTOBUF),
        );

        let response = PatchResponse { checked_patch };
        Ok((headers, response.encode().await?))
    }

    async fn rollback_rewind(
        log_type: &EventLogType,
        account: Arc<RwLock<AccountStorage>>,
        records: Vec<EventRecord>,
    ) -> Result<()> {
        let reader = account.read().await;
        match log_type {
            EventLogType::Identity => {
                let log = reader.storage.identity_log();
                let mut event_log = log.write().await;
                event_log.apply_records(records).await?;
            }
            EventLogType::Account => {
                let log = reader.storage.account_log();
                let mut event_log = log.write().await;
                event_log.apply_records(records).await?;
            }
            EventLogType::Device => {
                let log = reader.storage.device_log().await?;
                let mut event_log = log.write().await;
                event_log.apply_records(records).await?;
            }
            #[cfg(feature = "files")]
            EventLogType::Files => {
                let log = reader.storage.file_log().await?;
                let mut event_log = log.write().await;
                event_log.apply_records(records).await?;
            }
            EventLogType::Folder(id) => {
                let log = reader.storage.folder_log(id).await?;
                let mut event_log = log.write().await;
                event_log.apply_records(records).await?;
            }
        }

        Ok(())
    }

    pub(super) async fn sync_account(
        state: ServerState,
        backend: ServerBackend,
        caller: Caller,
        bytes: Bytes,
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

        let packet = SyncPacket::decode(bytes).await?;
        let (remote_status, diff) = (packet.status, packet.diff);

        // Apply the diff to the storage
        let mut outcome = MergeOutcome::default();
        let compare = {
            tracing::debug!("merge_server");
            let mut writer = account.write().await;
            writer.storage.merge(diff, &mut outcome).await?
        };

        // Generate a new diff so the client can apply changes
        // that exist in remote but not in the local
        let (local_status, diff) = {
            let reader = account.read().await;
            let (_, local_status, diff) =
                sos_protocol::diff(&reader.storage, remote_status).await?;
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
                let reader = state.read().await;
                send_notification(&*reader, &caller, notification).await;
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
            HeaderValue::from_static(MIME_TYPE_PROTOBUF),
        );

        Ok((headers, packet.encode().await?))
    }
}
