//! Server for the native messaging API bridge.

use http::{Request, Response, StatusCode};
use secrecy::SecretString;
use serde::Deserialize;
use sos_protocol::{Merge, SyncStorage};
use sos_sdk::prelude::{AccessKey, Account, ErrorExt, Identity};

use crate::web_service::{
    internal_server_error, json, parse_account_id, parse_json_body,
    parse_query,
};

use super::{status, Accounts, Body, Incoming};

#[derive(Deserialize)]
struct SigninRequest {
    password: String,
}

/// List account public identities.
pub async fn list_accounts<A, R, E>(
    _req: Request<Incoming>,
    accounts: Accounts<A, R, E>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    R: 'static,
    E: std::fmt::Debug
        + From<sos_sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    let accounts = accounts.read().await;
    let Ok(list) = Identity::list_accounts(accounts.data_dir()).await else {
        return internal_server_error("list_accounts");
    };

    json(StatusCode::OK, &list)
}

/// List account authenticated status.
pub async fn authenticated_accounts<A, R, E>(
    _req: Request<Incoming>,
    accounts: Accounts<A, R, E>,
) -> hyper::Result<Response<Body>>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    R: 'static,
    E: std::fmt::Debug
        + From<sos_sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    let accounts = accounts.read().await;
    let mut list = Vec::new();
    for account in accounts.iter() {
        let address = account.address().to_string();
        list.push((address, account.is_authenticated().await));
    }

    json(StatusCode::OK, &list)
}

/// Open a URL.
pub async fn open_url(
    req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    tracing::debug!(uri = %req.uri(), "open_url");

    let query = parse_query(req.uri());

    let Some(value) = query.get("url") else {
        return status(StatusCode::BAD_REQUEST);
    };

    tracing::debug!(url = %value, "open_url");

    match open::that_detached(value) {
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
        + ErrorExt
        + From<sos_sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    let Some(account_id) = parse_account_id(&req) else {
        return status(StatusCode::BAD_REQUEST);
    };

    let Ok(request) = parse_json_body::<SigninRequest>(req).await else {
        return status(StatusCode::BAD_REQUEST);
    };
    let password = request.password;

    tracing::debug!(account = %account_id, "sign_in");

    let mut accounts = accounts.write().await;
    let Some(account) =
        accounts.iter_mut().find(|a| a.address() == &account_id)
    else {
        return status(StatusCode::NOT_FOUND);
    };

    let password = SecretString::new(password.clone().into());
    let key: AccessKey = password.into();
    match account.sign_in(&key).await {
        Ok(_) => status(StatusCode::OK),
        Err(e) => {
            if e.is_permission_denied() {
                status(StatusCode::FORBIDDEN)
            } else {
                status(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
}

pub async fn has_keyring_credentials(
    req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    use keyring::{Entry, Error};
    use sos_sdk::constants::KEYRING_SERVICE;

    let Some(account_id) = parse_account_id(&req) else {
        return status(StatusCode::BAD_REQUEST);
    };

    let account_id = account_id.to_string();

    let service = format!("{} ({})", KEYRING_SERVICE, account_id);
    let Ok(entry) = Entry::new(&service, account_id.as_ref()) else {
        return status(StatusCode::INTERNAL_SERVER_ERROR);
    };

    match entry.get_password() {
        Ok(_) => status(StatusCode::OK),
        Err(e) => match e {
            Error::NoEntry => status(StatusCode::NOT_FOUND),
            _ => status(StatusCode::INTERNAL_SERVER_ERROR),
        },
    }
}

pub async fn sign_in_keyring<A, R, E>(
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
        + ErrorExt
        + From<sos_sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    use keyring::{Entry, Error};
    use sos_sdk::constants::KEYRING_SERVICE;

    let Some(account_id) = parse_account_id(&req) else {
        return status(StatusCode::BAD_REQUEST);
    };

    let entry_id = account_id.to_string();
    let service = format!("{} ({})", KEYRING_SERVICE, entry_id);
    let Ok(entry) = Entry::new(&service, entry_id.as_ref()) else {
        return status(StatusCode::INTERNAL_SERVER_ERROR);
    };

    match entry.get_password() {
        Ok(password) => {
            let mut accounts = accounts.write().await;
            let Some(account) =
                accounts.iter_mut().find(|a| a.address() == &account_id)
            else {
                return status(StatusCode::NOT_FOUND);
            };

            let password = SecretString::new(password.into());
            let key: AccessKey = password.into();
            match account.sign_in(&key).await {
                Ok(_) => status(StatusCode::OK),
                Err(e) => {
                    if e.is_permission_denied() {
                        status(StatusCode::FORBIDDEN)
                    } else {
                        status(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                }
            }
        }
        Err(e) => match e {
            Error::NoEntry => status(StatusCode::NOT_FOUND),
            _ => status(StatusCode::INTERNAL_SERVER_ERROR),
        },
    }
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
