//! Server for the native messaging API bridge.

use http::{Request, Response, StatusCode};
use secrecy::SecretString;
use sos_protocol::{Merge, SyncStorage};
use sos_sdk::{
    prelude::{AccessKey, Account, AccountSwitcher, Address},
    url::form_urlencoded,
};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{status, Body, Incoming};

/// Collection of accounts.
pub type Accounts<A, R, E> = Arc<RwLock<AccountSwitcher<A, R, E>>>;

/// Open a URL.
pub async fn open_url(
    req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    tracing::debug!(uri = %req.uri(), "open_url");

    let uri = req.uri().to_string();
    let parts = uri.splitn(2, "?");
    let Some(query) = parts.last() else {
        return status(StatusCode::BAD_REQUEST);
    };

    tracing::debug!(query = %query, "open_url");

    let mut it = form_urlencoded::parse(query.as_bytes());
    let Some((_, value)) = it.find(|(name, _)| name == "url") else {
        return status(StatusCode::BAD_REQUEST);
    };

    tracing::debug!(url = %value, "open_url");

    match open::that_detached(value.as_ref()) {
        Ok(_) => status(StatusCode::OK),
        Err(_) => status(StatusCode::BAD_GATEWAY),
    }
}

/// Sign in to an account
pub async fn sign_in<A, R, E>(
    req: Request<Incoming>,
    accounts: Accounts<A, R, E>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R>
        + SyncStorage
        + Merge
        + Sync
        + Send
        + 'static,
    R: 'static,
    E: std::fmt::Debug
        + From<sos_sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    let uri = req.uri().to_string();
    let parts = uri.splitn(2, "?");
    let Some(query) = parts.last() else {
        return status(StatusCode::BAD_REQUEST);
    };

    let mut it = form_urlencoded::parse(query.as_bytes());
    let Some((_, account)) = it.find(|(name, _)| name == "account") else {
        return status(StatusCode::BAD_REQUEST);
    };

    let Some((_, password)) = it.find(|(name, _)| name == "password") else {
        return status(StatusCode::BAD_REQUEST);
    };

    let Ok(account_id) = account.parse::<Address>() else {
        return status(StatusCode::BAD_REQUEST);
    };

    tracing::debug!(account = %account, "sign_in");

    let mut accounts = accounts.write().await;
    let Some(account) =
        accounts.iter_mut().find(|a| a.address() == &account_id)
    else {
        return status(StatusCode::NOT_FOUND);
    };

    let password = SecretString::new(password.into());
    let key: AccessKey = password.into();
    if account.sign_in(&key).await.is_err() {
        return status(StatusCode::INTERNAL_SERVER_ERROR);
    };

    status(StatusCode::OK)
}

#[cfg(debug_assertions)]
pub async fn large_file(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    use bytes::Bytes;
    use http_body_util::Full;
    const MB: usize = 1024 * 1024;
    let body = [255u8; MB].to_vec();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}
