//! Server for the native messaging API bridge.

use http::{Request, Response, StatusCode};
use secrecy::SecretString;
use serde::Deserialize;
use sos_protocol::{Merge, SyncStorage};
use sos_sdk::prelude::{
    AccessKey, Account, Address, ArchiveFilter, DocumentView, ErrorExt,
    Identity, QueryFilter, SecretPath,
};
use std::collections::HashMap;

use crate::web_service::{
    internal_server_error, json, parse_account_id, parse_json_body,
    parse_query,
};

use super::{status, Accounts, Body, Incoming};

#[derive(Deserialize)]
struct SigninRequest {
    password: String,
}

#[derive(Deserialize)]
struct SearchRequest {
    needle: String,
    filter: QueryFilter,
}

#[derive(Deserialize)]
struct QueryViewRequest {
    views: Vec<DocumentView>,
    archive_filter: Option<ArchiveFilter>,
}

#[derive(Deserialize)]
struct CopyRequest {
    path: SecretPath,
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
        + std::error::Error
        + From<sos_sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    let accounts = accounts.read().await;
    let Ok(list) = Identity::list_accounts(accounts.paths()).await else {
        return internal_server_error("list_accounts");
    };

    json(StatusCode::OK, &list)
}

/// List folders for authenticated accounts.
pub async fn list_folders<A, R, E>(
    _req: Request<Incoming>,
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
    let accounts = accounts.read().await;
    let mut list = HashMap::new();
    for account in accounts.iter() {
        let address = account.address().to_string();
        if account.is_authenticated().await {
            let Ok(folders) = account.list_folders().await else {
                return internal_server_error("list_folders");
            };
            list.insert(address, folders);
        }
    }
    json(StatusCode::OK, &list)
}

/// Search authenticated accounts.
pub async fn search<A, R, E>(
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
    let Ok(request) = parse_json_body::<SearchRequest>(req).await else {
        return status(StatusCode::BAD_REQUEST);
    };

    let accounts = accounts.read().await;
    let Ok(results) = accounts.search(request.needle, request.filter).await
    else {
        return internal_server_error("search");
    };

    let list = results
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect::<HashMap<_, _>>();

    json(StatusCode::OK, &list)
}

/// Query a search index view for authenticated accounts.
pub async fn query_view<A, R, E>(
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
    let Ok(request) = parse_json_body::<QueryViewRequest>(req).await else {
        return status(StatusCode::BAD_REQUEST);
    };

    let accounts = accounts.read().await;
    let Ok(results) = accounts
        .query_view(request.views.as_slice(), request.archive_filter.as_ref())
        .await
    else {
        return internal_server_error("search");
    };

    let list = results
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect::<HashMap<_, _>>();

    json(StatusCode::OK, &list)
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

    let Ok(request) = parse_json_body::<CopyRequest>(req).await else {
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

/// List account authenticated status.
pub async fn authenticated_accounts<A, R, E>(
    _req: Request<Incoming>,
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
pub async fn sign_in_account<A, R, E>(
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
        + std::error::Error
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

    sign_in_password(accounts, account_id, password).await
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
        + std::error::Error
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
            sign_in_password(accounts, account_id, password).await
        }
        Err(e) => match e {
            Error::NoEntry => status(StatusCode::NOT_FOUND),
            _ => status(StatusCode::INTERNAL_SERVER_ERROR),
        },
    }
}

/// Sign in to an account
pub async fn sign_in_password<A, R, E>(
    accounts: Accounts<A, R, E>,
    account_id: Address,
    password: String,
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
        + std::error::Error
        + ErrorExt
        + From<sos_sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    let mut accounts = accounts.write().await;
    let Some(account) =
        accounts.iter_mut().find(|a| a.address() == &account_id)
    else {
        return status(StatusCode::NOT_FOUND);
    };

    let password = SecretString::new(password.into());
    let key: AccessKey = password.into();
    if let Err(e) = account.sign_in(&key).await {
        if e.is_permission_denied() {
            return status(StatusCode::FORBIDDEN);
        } else {
            return status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    if account.initialize_search_index().await.is_err() {
        return internal_server_error("sign_in::search_index");
    }

    status(StatusCode::OK)
}

/// Sign out of an account
pub async fn sign_out_account<A, R, E>(
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
        + std::error::Error
        + ErrorExt
        + From<sos_sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    let Some(account_id) = parse_account_id(&req) else {
        return status(StatusCode::BAD_REQUEST);
    };

    tracing::debug!(account = %account_id, "sign_out::account");

    sign_out(accounts, Some(account_id)).await
}

/// Sign out of all accounts
pub async fn sign_out_all<A, R, E>(
    _req: Request<Incoming>,
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
        + std::error::Error
        + ErrorExt
        + From<sos_sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    tracing::debug!("sign_out::all");
    sign_out(accounts, None).await
}

/// Sign out of an account
pub async fn sign_out<A, R, E>(
    accounts: Accounts<A, R, E>,
    account_id: Option<Address>,
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
        + std::error::Error
        + ErrorExt
        + From<sos_sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    let mut accounts = accounts.write().await;

    if let Some(account_id) = account_id {
        let Some(account) =
            accounts.iter_mut().find(|a| a.address() == &account_id)
        else {
            return status(StatusCode::NOT_FOUND);
        };

        match account.sign_out().await {
            Ok(_) => status(StatusCode::OK),
            Err(_) => status(StatusCode::INTERNAL_SERVER_ERROR),
        }
    } else {
        match accounts.sign_out_all().await {
            Ok(_) => status(StatusCode::OK),
            Err(_) => status(StatusCode::INTERNAL_SERVER_ERROR),
        }
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
