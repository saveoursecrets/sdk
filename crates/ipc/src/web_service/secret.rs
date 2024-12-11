//! Server for the native messaging API bridge.

use http::{Request, Response, StatusCode};
use serde::Deserialize;
use sos_sdk::prelude::{Account, ClipboardCopyRequest, SecretPath};

use crate::web_service::{
    json, parse_account_id, parse_json_body, status, Accounts, Body, Incoming,
};

#[derive(Deserialize)]
struct CopyRequest {
    target: SecretPath,
    request: Option<ClipboardCopyRequest>,
}

/// Copy a secret to the clipboard.
#[cfg(feature = "clipboard")]
pub async fn copy_secret_clipboard<A, R, E>(
    req: Request<Incoming>,
    accounts: Accounts<A, R, E>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    R: 'static,
    E: std::fmt::Debug
        + std::error::Error
        + From<sos_sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    let Some(account_id) = parse_account_id(&req) else {
        return status(StatusCode::BAD_REQUEST);
    };

    let Ok(mut payload) = parse_json_body::<CopyRequest>(req).await else {
        return status(StatusCode::BAD_REQUEST);
    };

    let request = payload.request.take().unwrap_or_default();
    let accounts = accounts.read().await;
    match accounts
        .copy_clipboard(&account_id, &payload.target, &request)
        .await
    {
        Ok(result) => json(StatusCode::OK, &result),
        Err(e) => {
            tracing::error!(error = %e, "copy_clipboard");
            status(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Read a secret.
pub async fn read_secret<A, R, E>(
    req: Request<Incoming>,
    accounts: Accounts<A, R, E>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    R: 'static,
    E: std::fmt::Debug
        + std::error::Error
        + From<sos_sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    let Some(account_id) = parse_account_id(&req) else {
        return status(StatusCode::BAD_REQUEST);
    };

    let accounts = accounts.read().await;
    let Some(account) = accounts.iter().find(|a| a.address() == &account_id)
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

    match account.read_secret(request.secret_id(), Some(folder)).await {
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
            status(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
