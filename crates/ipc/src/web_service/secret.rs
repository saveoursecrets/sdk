//! Server for the native messaging API bridge.

use http::{Request, Response, StatusCode};
use serde::Deserialize;
use sos_sdk::prelude::{Account, SecretPath};

use crate::web_service::{
    json, parse_account_id, parse_json_body, status, Accounts, Body, Incoming,
};

#[derive(Deserialize)]
struct SecretRequest {
    path: SecretPath,
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

    let Ok(request) = parse_json_body::<SecretRequest>(req).await else {
        return status(StatusCode::BAD_REQUEST);
    };

    let accounts = accounts.read().await;
    match accounts.copy_clipboard(&account_id, request.path).await {
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

    let Ok(request) = parse_json_body::<SecretRequest>(req).await else {
        return status(StatusCode::BAD_REQUEST);
    };

    let accounts = accounts.read().await;
    match accounts.copy_clipboard(&account_id, request.path).await {
        Ok(result) => json(StatusCode::OK, &result),
        Err(e) => {
            tracing::error!(error = %e, "copy_clipboard");
            status(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
