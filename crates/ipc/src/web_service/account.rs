//! Account and folder routes.

use http::{Request, Response, StatusCode};
use secrecy::SecretString;
use serde::Deserialize;
use sos_protocol::{Merge, SyncStorage};
use sos_sdk::prelude::{AccessKey, Account, Address, ErrorExt, Identity};
use std::collections::HashMap;

use crate::web_service::{
    internal_server_error, json, parse_account_id, parse_json_body, status,
    Accounts, Body, Incoming,
};

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
        + std::error::Error
        + From<sos_sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    let accounts = accounts.read().await;
    match Identity::list_accounts(accounts.paths()).await {
        Ok(list) => json(StatusCode::OK, &list),
        Err(e) => internal_server_error(e),
    }
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
            match account.list_folders().await {
                Ok(folders) => {
                    list.insert(address, folders);
                }
                Err(e) => {
                    return internal_server_error(e);
                }
            }
        }
    }
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
        + std::error::Error
        + From<sos_sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    let accounts = accounts.read().await;
    let mut list = HashMap::new();
    for account in accounts.iter() {
        let address = account.address().to_string();
        list.insert(address.to_string(), account.is_authenticated().await);
    }
    json(StatusCode::OK, &list)
}

/// Sign in to an account with a user-supplied password.
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

#[deprecated]
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
    match Entry::new(&service, account_id.as_ref()) {
        Ok(entry) => match entry.get_password() {
            Ok(_) => status(StatusCode::OK),
            Err(e) => match e {
                Error::NoEntry => status(StatusCode::NOT_FOUND),
                _ => internal_server_error(e),
            },
        },
        Err(e) => internal_server_error(e),
    }
}

#[cfg(target_os = "macos")]
pub async fn sign_in_device_auth<A, R, E>(
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
    use sos_platform_authenticator::{keyring_password, local_auth};

    tracing::debug!(
        local_auth_supported = %local_auth::supported(),
    );

    if local_auth::supported() {
        if local_auth::authenticate(Default::default()) {
            let Some(account_id) = parse_account_id(&req) else {
                return status(StatusCode::BAD_REQUEST);
            };

            match keyring_password::find_account_password(
                &account_id.to_string(),
            ) {
                Ok(password) => {
                    tracing::debug!(
                        "got password from keyring, do authentication!!!!"
                    );
                    sign_in_password(accounts, account_id, password).await
                }
                Err(e) => internal_server_error(e),
            }
        } else {
            status(StatusCode::FORBIDDEN)
        }
    } else {
        status(StatusCode::NETWORK_AUTHENTICATION_REQUIRED)
    }
}

#[deprecated]
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
    match Entry::new(&service, entry_id.as_ref()) {
        Ok(entry) => match entry.get_password() {
            Ok(password) => {
                sign_in_password(accounts, account_id, password).await
            }
            Err(e) => match e {
                Error::NoEntry => status(StatusCode::NOT_FOUND),
                _ => internal_server_error(e),
            },
        },
        Err(e) => internal_server_error(e),
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
            return internal_server_error(e);
        }
    }

    if let Err(e) = account.initialize_search_index().await {
        return internal_server_error(e);
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
            Err(e) => internal_server_error(e),
        }
    } else {
        match accounts.sign_out_all().await {
            Ok(_) => status(StatusCode::OK),
            Err(e) => internal_server_error(e),
        }
    }
}
