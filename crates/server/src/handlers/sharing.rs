use super::{BODY_LIMIT, Caller, parse_account_id};
use crate::{ServerBackend, ServerState, handlers::authenticate_endpoint};
use axum::{
    body::{Body, to_bytes},
    extract::Extension,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use axum_extra::{
    headers::{Authorization, authorization::Bearer},
    typed_header::TypedHeader,
};
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

mod handlers {
    use super::Caller;
    use crate::{Error, Result, ServerBackend, ServerState};
    use axum::body::Bytes;
    use http::header::{self, HeaderMap, HeaderValue};
    use sos_protocol::{
        SetRecipientRequest, SetRecipientResponse, SharedFolderRequest,
        SharedFolderResponse, WireEncodeDecode,
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
}
