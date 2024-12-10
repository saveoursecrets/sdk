//! Server for the native messaging API bridge.

use http::{Request, Response, StatusCode};
use sos_sdk::prelude::{Account, SecretPath};

use crate::web_service::{
    json, parse_account_id, parse_json_body, status, Accounts, Body, Incoming,
};

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

    let Ok(request) = parse_json_body::<SecretPath>(req).await else {
        return status(StatusCode::BAD_REQUEST);
    };

    let accounts = accounts.read().await;
    match accounts.copy_clipboard(&account_id, &request).await {
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
        Ok(result) => json(StatusCode::OK, &result.0),
        Err(e) => {
            tracing::error!(error = %e, "read_secret");
            status(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
