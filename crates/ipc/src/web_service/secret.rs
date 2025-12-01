//! Server for the native messaging API bridge.

use http::{Request, Response, StatusCode};
use serde::Deserialize;
use sos_account::{Account, ClipboardCopyRequest};
use sos_core::{ErrorExt, SecretPath};
use sos_sync::SyncStorage;

use crate::web_service::{
    Body, Incoming, WebAccounts, internal_server_error, json,
    parse_account_id, parse_json_body, status,
};

#[derive(Deserialize)]
struct CopyRequest {
    target: SecretPath,
    request: Option<ClipboardCopyRequest>,
}

/*
#[derive(Deserialize)]
struct FavoriteRequest {
    target: SecretPath,
    value: bool,
}
*/

/// Copy a secret to the clipboard.
#[cfg(feature = "clipboard")]
pub async fn copy_secret_clipboard<A, R, E>(
    req: Request<Incoming>,
    accounts: WebAccounts<A, R, E>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R> + SyncStorage,
    R: 'static,
    E: std::fmt::Debug
        + ErrorExt
        + std::error::Error
        + From<sos_core::Error>
        + From<sos_database::Error>
        + From<sos_account::Error>
        + From<sos_backend::Error>
        + From<sos_vault::Error>
        + From<sos_search::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    use crate::web_service::internal_server_error;

    let Some(account_id) = parse_account_id(&req) else {
        return status(StatusCode::BAD_REQUEST);
    };

    let Ok(mut payload) = parse_json_body::<CopyRequest>(req).await else {
        return status(StatusCode::BAD_REQUEST);
    };

    let request = payload.request.take().unwrap_or_default();
    let accounts = accounts.as_ref().read().await;
    match accounts
        .copy_clipboard(&account_id, &payload.target, &request)
        .await
    {
        Ok(result) => json(StatusCode::OK, &result),
        Err(e) => {
            tracing::error!(error = %e, "copy_clipboard");
            internal_server_error(e)
        }
    }
}

/// Read a secret.
pub async fn read_secret<A, R, E>(
    req: Request<Incoming>,
    accounts: WebAccounts<A, R, E>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R> + SyncStorage,
    R: 'static,
    E: std::fmt::Debug
        + ErrorExt
        + std::error::Error
        + From<sos_core::Error>
        + From<sos_database::Error>
        + From<sos_account::Error>
        + From<sos_backend::Error>
        + From<sos_vault::Error>
        + From<sos_search::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    let Some(account_id) = parse_account_id(&req) else {
        return status(StatusCode::BAD_REQUEST);
    };

    let accounts = accounts.as_ref().read().await;
    let Some(account) =
        accounts.iter().find(|a| a.account_id() == &account_id)
    else {
        return status(StatusCode::NOT_FOUND);
    };

    let Ok(request) = parse_json_body::<SecretPath>(req).await else {
        return status(StatusCode::BAD_REQUEST);
    };

    let Some(folder) = account.find(|f| f.id() == request.folder_id()).await
    else {
        return status(StatusCode::NOT_FOUND);
    };

    match account
        .read_secret(request.secret_id(), Some(folder.id()))
        .await
    {
        Ok(result) => {
            let mut secret_row = result.0;
            let redacted = secret_row.secret_mut().redact(true, 12);
            tracing::debug!(
              kind = %secret_row.meta().kind(),
              redacted = %redacted,
              "read_secret");
            json(StatusCode::OK, &secret_row)
        }
        Err(e) => {
            tracing::error!(error = %e, "read_secret");
            internal_server_error(e)
        }
    }
}

/*
/// Set favorite flag.
pub async fn set_favorite<A, R, E>(
    req: Request<Incoming>,
    accounts: WebAccounts<A, R, E>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R>
        + SyncStorage,
    R: 'static,
    E: std::fmt::Debug
        + ErrorExt
        + std::error::Error
        + From<sos_core::Error>
        + From<sos_database::Error>
        + From<sos_account::Error>
        + From<sos_backend::Error>
        + From<sos_vault::Error>
        + From<sos_search::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    let Some(account_id) = parse_account_id(&req) else {
        return status(StatusCode::BAD_REQUEST);
    };

    let mut accounts = accounts.as_ref().write().await;
    let Some(account) =
        accounts.iter_mut().find(|a| a.account_id() == &account_id)
    else {
        return status(StatusCode::NOT_FOUND);
    };

    let Ok(request) = parse_json_body::<FavoriteRequest>(req).await else {
        return status(StatusCode::BAD_REQUEST);
    };

    let Some(folder) =
        account.find(|f| f.id() == request.target.folder_id()).await
    else {
        return status(StatusCode::NOT_FOUND);
    };

    let result = account
        .read_secret(request.target.secret_id(), Some(folder))
        .await;
    match result {
        Ok(result) => {
            let mut secret_row = result.0;
            secret_row.meta_mut().set_favorite(request.value);

            let (id, meta, secret) = secret_row.into();
            if let Err(e) = account
                .update_secret(
                    &id,
                    meta,
                    Some(secret),
                    Default::default(),
                    None,
                )
                .await
            {
                return internal_server_error(e);
            }

            status(StatusCode::OK)
        }
        Err(e) => {
            if e.is_secret_not_found() {
                return status(StatusCode::NOT_FOUND);
            }
            tracing::error!(error = %e, "read_secret");
            internal_server_error(e)
        }
    }
}
*/

#[cfg(feature = "contacts")]
pub async fn load_avatar<A, R, E>(
    req: Request<Incoming>,
    accounts: WebAccounts<A, R, E>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R> + SyncStorage,
    R: 'static,
    E: std::fmt::Debug
        + ErrorExt
        + std::error::Error
        + From<sos_core::Error>
        + From<sos_database::Error>
        + From<sos_account::Error>
        + From<sos_backend::Error>
        + From<sos_vault::Error>
        + From<sos_search::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    use crate::web_service::text;
    use base64::prelude::*;

    let Some(account_id) = parse_account_id(&req) else {
        return status(StatusCode::BAD_REQUEST);
    };

    let accounts = accounts.as_ref().read().await;
    let Some(account) =
        accounts.iter().find(|a| a.account_id() == &account_id)
    else {
        return status(StatusCode::NOT_FOUND);
    };

    let Ok(request) = parse_json_body::<SecretPath>(req).await else {
        return status(StatusCode::BAD_REQUEST);
    };

    let Some(folder) = account.find(|f| f.id() == request.folder_id()).await
    else {
        return status(StatusCode::NOT_FOUND);
    };

    match account
        .load_avatar(request.secret_id(), Some(folder.id()))
        .await
    {
        Ok(maybe_avatar) => {
            let Some(png_bytes) = maybe_avatar else {
                return status(StatusCode::NOT_FOUND);
            };
            let encoded = BASE64_STANDARD.encode(&png_bytes);
            text(
                StatusCode::OK,
                format!("data:image/jpeg;base64,{}", encoded),
            )
        }
        Err(e) => internal_server_error(e),
    }
}
