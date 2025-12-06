use super::{BODY_LIMIT, Caller, parse_account_id};
use crate::{ServerBackend, ServerState, handlers::authenticate_endpoint};
use axum::{
    body::{Body, to_bytes},
    extract::{Extension, OriginalUri, Query},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use axum_extra::{
    headers::{Authorization, authorization::Bearer},
    typed_header::TypedHeader,
};
use sos_protocol::GetFolderInvitesRequest;
use std::sync::Arc;

/// Upsert account recipient information.
#[utoipa::path(
    put,
    path = "/sharing/recipient",
    security(
        ("bearer_token" = [])
    ),
    request_body(
        content_type = "application/octet-stream",
        content = Vec<u8>,
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
            description = "Recipient information was inserted or updated.",
        ),
    ),
)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn set_recipient(
    Extension(state): Extension<ServerState>,
    Extension(backend): Extension<ServerBackend>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    headers: HeaderMap,
    body: Body,
) -> impl IntoResponse {
    let account_id = parse_account_id(&headers);
    match to_bytes(body, BODY_LIMIT).await {
        Ok(bytes) => match authenticate_endpoint(
            account_id,
            bearer,
            &bytes,
            None,
            Arc::clone(&state),
            Arc::clone(&backend),
        )
        .await
        {
            Ok(caller) => {
                match handlers::set_recipient(state, backend, caller, bytes)
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

/// Get account recipient information.
#[utoipa::path(
    get,
    path = "/sharing/recipient",
    security(
        ("bearer_token" = [])
    ),
    request_body(
        content_type = "application/octet-stream",
        content = Vec<u8>,
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
            description = "Recipient information was fetched.",
        ),
    ),
)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn get_recipient(
    Extension(state): Extension<ServerState>,
    Extension(backend): Extension<ServerBackend>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let uri = uri.path().to_string();
    let account_id = parse_account_id(&headers);
    match authenticate_endpoint(
        account_id,
        bearer,
        uri.as_bytes(),
        None,
        Arc::clone(&state),
        Arc::clone(&backend),
    )
    .await
    {
        Ok(caller) => {
            match handlers::get_recipient(state, backend, caller).await {
                Ok(response) => response.into_response(),
                Err(error) => error.into_response(),
            }
        }
        Err(error) => error.into_response(),
    }
}

/// Create a shared folder.
#[utoipa::path(
    post,
    path = "/sharing/folder",
    security(
        ("bearer_token" = [])
    ),
    request_body(
        content_type = "application/octet-stream",
        content = Vec<u8>,
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
            description = "Folder was created.",
        ),
    ),
)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_folder(
    Extension(state): Extension<ServerState>,
    Extension(backend): Extension<ServerBackend>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    headers: HeaderMap,
    body: Body,
) -> impl IntoResponse {
    let account_id = parse_account_id(&headers);
    match to_bytes(body, BODY_LIMIT).await {
        Ok(bytes) => match authenticate_endpoint(
            account_id,
            bearer,
            &bytes,
            None,
            Arc::clone(&state),
            Arc::clone(&backend),
        )
        .await
        {
            Ok(caller) => {
                match handlers::create_folder(state, backend, caller, bytes)
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

/// Get sent folder invites.
#[utoipa::path(
    get,
    path = "/sharing/folder/invites/sent",
    security(
        ("bearer_token" = [])
    ),
    request_body(
        content_type = "application/octet-stream",
        content = Vec<u8>,
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
            description = "List of folder invites.",
        ),
    ),
)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn sent_folder_invites(
    Extension(state): Extension<ServerState>,
    Extension(backend): Extension<ServerBackend>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    Query(params): Query<GetFolderInvitesRequest>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let uri = uri.path().to_string();
    let account_id = parse_account_id(&headers);
    match authenticate_endpoint(
        account_id,
        bearer,
        uri.as_bytes(),
        None,
        Arc::clone(&state),
        Arc::clone(&backend),
    )
    .await
    {
        Ok(caller) => {
            match handlers::sent_folder_invites(
                state, backend, caller, params,
            )
            .await
            {
                Ok(response) => response.into_response(),
                Err(error) => error.into_response(),
            }
        }
        Err(error) => error.into_response(),
    }
}

/// Get received folder invites.
#[utoipa::path(
    get,
    path = "/sharing/folder/invites/inbox",
    security(
        ("bearer_token" = [])
    ),
    request_body(
        content_type = "application/octet-stream",
        content = Vec<u8>,
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
            description = "List of folder invites.",
        ),
    ),
)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn received_folder_invites(
    Extension(state): Extension<ServerState>,
    Extension(backend): Extension<ServerBackend>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    Query(params): Query<GetFolderInvitesRequest>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let uri = uri.path().to_string();
    let account_id = parse_account_id(&headers);
    match authenticate_endpoint(
        account_id,
        bearer,
        uri.as_bytes(),
        None,
        Arc::clone(&state),
        Arc::clone(&backend),
    )
    .await
    {
        Ok(caller) => {
            match handlers::received_folder_invites(
                state, backend, caller, params,
            )
            .await
            {
                Ok(response) => response.into_response(),
                Err(error) => error.into_response(),
            }
        }
        Err(error) => error.into_response(),
    }
}

/// Update a folder invite.
#[utoipa::path(
    put,
    path = "/sharing/folder/invites",
    security(
        ("bearer_token" = [])
    ),
    request_body(
        content_type = "application/octet-stream",
        content = Vec<u8>,
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
            description = "Folder invite was updated.",
        ),
    ),
)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn update_folder_invite(
    Extension(state): Extension<ServerState>,
    Extension(backend): Extension<ServerBackend>,
    TypedHeader(bearer): TypedHeader<Authorization<Bearer>>,
    headers: HeaderMap,
    body: Body,
) -> impl IntoResponse {
    let account_id = parse_account_id(&headers);
    match to_bytes(body, BODY_LIMIT).await {
        Ok(bytes) => match authenticate_endpoint(
            account_id,
            bearer,
            &bytes,
            None,
            Arc::clone(&state),
            Arc::clone(&backend),
        )
        .await
        {
            Ok(caller) => {
                match handlers::update_folder_invite(
                    state, backend, caller, bytes,
                )
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
    use crate::{Error, Result, ServerBackend, ServerState};
    use axum::body::Bytes;
    use http::header::{self, HeaderMap, HeaderValue};
    use sos_protocol::{
        GetFolderInvitesRequest, GetFolderInvitesResponse,
        GetRecipientResponse, SetRecipientRequest, SetRecipientResponse,
        SharedFolderRequest, SharedFolderResponse, UpdateFolderInviteRequest,
        UpdateFolderInviteResponse, WireEncodeDecode,
        constants::MIME_TYPE_PROTOBUF,
    };
    use sos_server_storage::ServerAccountStorage;
    use std::sync::Arc;

    pub(super) async fn set_recipient(
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
                .get(caller.account_id())
                .ok_or_else(|| Error::NoAccount(*caller.account_id()))?;
            Arc::clone(account)
        };

        let packet = SetRecipientRequest::decode(bytes).await?;

        {
            let mut account = account.write().await;
            account.set_recipient(packet.recipient).await?;
        }

        // Empty response packet for now
        let packet = SetRecipientResponse {};

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_PROTOBUF),
        );

        Ok((headers, packet.encode().await?))
    }

    pub(super) async fn get_recipient(
        _state: ServerState,
        backend: ServerBackend,
        caller: Caller,
    ) -> Result<(HeaderMap, Vec<u8>)> {
        let account = {
            let reader = backend.read().await;
            let accounts = reader.accounts();
            let reader = accounts.read().await;
            let account = reader
                .get(caller.account_id())
                .ok_or_else(|| Error::NoAccount(*caller.account_id()))?;
            Arc::clone(account)
        };

        let recipient = {
            let mut account = account.write().await;
            account.get_recipient().await?
        };

        // Empty response packet for now
        let packet = GetRecipientResponse { recipient };

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_PROTOBUF),
        );

        Ok((headers, packet.encode().await?))
    }

    pub(super) async fn create_folder(
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
                .get(caller.account_id())
                .ok_or_else(|| Error::NoAccount(*caller.account_id()))?;
            Arc::clone(account)
        };

        let packet = SharedFolderRequest::decode(bytes).await?;

        {
            let mut account = account.write().await;
            account
                .create_shared_folder(
                    &packet.vault,
                    packet.recipients.as_slice(),
                )
                .await?;
            // account.set_recipient(packet.recipient).await?;
        }

        // Empty response packet for now
        let packet = SharedFolderResponse {};

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_PROTOBUF),
        );

        Ok((headers, packet.encode().await?))
    }

    pub(super) async fn sent_folder_invites(
        _state: ServerState,
        backend: ServerBackend,
        caller: Caller,
        params: GetFolderInvitesRequest,
    ) -> Result<(HeaderMap, Vec<u8>)> {
        let account = {
            let reader = backend.read().await;
            let accounts = reader.accounts();
            let reader = accounts.read().await;
            let account = reader
                .get(caller.account_id())
                .ok_or_else(|| Error::NoAccount(*caller.account_id()))?;
            Arc::clone(account)
        };

        let folder_invites = {
            let mut account = account.write().await;
            account
                .sent_folder_invites(params.invite_status, params.limit)
                .await?
        };
        let packet = GetFolderInvitesResponse { folder_invites };

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_PROTOBUF),
        );

        Ok((headers, packet.encode().await?))
    }

    pub(super) async fn received_folder_invites(
        _state: ServerState,
        backend: ServerBackend,
        caller: Caller,
        params: GetFolderInvitesRequest,
    ) -> Result<(HeaderMap, Vec<u8>)> {
        let account = {
            let reader = backend.read().await;
            let accounts = reader.accounts();
            let reader = accounts.read().await;
            let account = reader
                .get(caller.account_id())
                .ok_or_else(|| Error::NoAccount(*caller.account_id()))?;
            Arc::clone(account)
        };

        let folder_invites = {
            let mut account = account.write().await;
            account
                .received_folder_invites(params.invite_status, params.limit)
                .await?
        };
        let packet = GetFolderInvitesResponse { folder_invites };

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_PROTOBUF),
        );

        Ok((headers, packet.encode().await?))
    }

    pub(super) async fn update_folder_invite(
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
                .get(caller.account_id())
                .ok_or_else(|| Error::NoAccount(*caller.account_id()))?;
            Arc::clone(account)
        };

        let params = UpdateFolderInviteRequest::decode(bytes).await?;
        let mut account = account.write().await;
        account
            .update_folder_invite(
                params.invite_status,
                params.from_public_key.to_string(),
                params.folder_id,
            )
            .await?;
        let packet = UpdateFolderInviteResponse {};

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_PROTOBUF),
        );

        Ok((headers, packet.encode().await?))
    }
}
