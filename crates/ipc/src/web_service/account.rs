//! Account and folder routes.

use http::{Request, Response, StatusCode};
use secrecy::SecretString;
use serde::Deserialize;
use sos_account::Account;
use sos_sdk::prelude::{AccessKey, Address, ErrorExt, Identity};
use sos_sync::{Merge, SyncStorage};
use std::collections::HashMap;

use crate::web_service::{
    internal_server_error, json, parse_account_id, parse_json_body, status,
    Body, Incoming, WebAccounts,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigninRequest {
    password: String,
    save_password: bool,
}

/// List account public identities.
pub async fn list_accounts<A, R, E>(
    _req: Request<Incoming>,
    accounts: WebAccounts<A, R, E>,
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
        + std::error::Error
        + From<sos_sdk::Error>
        + From<sos_database::Error>
        + From<sos_account::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    let accounts = accounts.as_ref().read().await;
    match Identity::list_accounts(accounts.paths()).await {
        Ok(list) => json(StatusCode::OK, &list),
        Err(e) => internal_server_error(e),
    }
}

/// List folders for authenticated accounts.
pub async fn list_folders<A, R, E>(
    _req: Request<Incoming>,
    accounts: WebAccounts<A, R, E>,
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
        + std::error::Error
        + From<sos_sdk::Error>
        + From<sos_database::Error>
        + From<sos_account::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    let accounts = accounts.as_ref().read().await;
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
    accounts: WebAccounts<A, R, E>,
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
        + std::error::Error
        + From<sos_sdk::Error>
        + From<sos_database::Error>
        + From<sos_account::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    let accounts = accounts.as_ref().read().await;
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
    accounts: WebAccounts<A, R, E>,
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
        + From<sos_database::Error>
        + From<sos_account::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    let Some(account_id) = parse_account_id(&req) else {
        return status(StatusCode::BAD_REQUEST);
    };

    let Ok(request) = parse_json_body::<SigninRequest>(req).await else {
        return status(StatusCode::BAD_REQUEST);
    };

    tracing::debug!(account = %account_id, "sign_in");

    let password = SecretString::new(request.password.into());
    sign_in_password(accounts, account_id, password, request.save_password)
        .await
}

/// Sign in to an account attempting to retrieve the account
/// password from the platform keyring.
///
/// If a platform authenticator or platform keyring is not supported
/// this will return `StatusCode::UNAUTHORIZED` and the user will
/// need to supply their password and
pub async fn sign_in<A, R, E>(
    req: Request<Incoming>,
    accounts: WebAccounts<A, R, E>,
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
        + From<sos_database::Error>
        + From<sos_account::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    use sos_platform_authenticator::{
        find_account_credential, keyring_password, local_auth,
    };

    let Some(account_id) = parse_account_id(&req) else {
        return status(StatusCode::BAD_REQUEST);
    };

    tracing::debug!(
        account_id = %account_id,
        local_auth_supported = %local_auth::supported(),
        keyring_password_supported = %keyring_password::supported(),
    );

    match find_account_credential(&account_id.to_string()).await {
        Ok(password) => {
            sign_in_password(accounts, account_id, password, false).await
        }
        Err(e) => {
            let code: StatusCode = (&e).into();
            match code {
                StatusCode::INTERNAL_SERVER_ERROR => internal_server_error(e),
                StatusCode::NOT_FOUND => status(StatusCode::UNAUTHORIZED),
                _ => status(code),
            }
        }
    }
}

/// Sign in to an account
pub async fn sign_in_password<A, R, E>(
    accounts: WebAccounts<A, R, E>,
    account_id: Address,
    password: SecretString,
    save_password: bool,
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
        + From<sos_database::Error>
        + From<sos_account::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    use sos_platform_authenticator::keyring_password;

    let mut user_accounts = accounts.as_ref().write().await;
    let Some(account) = user_accounts
        .iter_mut()
        .find(|a| a.address() == &account_id)
    else {
        return status(StatusCode::NOT_FOUND);
    };

    let key: AccessKey = password.clone().into();

    let folder_ids = if let Ok(folders) = account.list_folders().await {
        folders.into_iter().map(|f| *f.id()).collect::<Vec<_>>()
    } else {
        vec![]
    };

    match account.sign_in(&key).await {
        Ok(_) => {
            if let Err(e) =
                accounts.watch(account_id, account.paths(), folder_ids)
            {
                tracing::error!(error = ?e);
            }
        }
        Err(e) => {
            if e.is_permission_denied() {
                return status(StatusCode::FORBIDDEN);
            } else {
                return internal_server_error(e);
            }
        }
    }

    if let Err(e) = account.initialize_search_index().await {
        return internal_server_error(e);
    }

    if save_password && keyring_password::supported() {
        if let Err(e) = keyring_password::save_account_password(
            &account_id.to_string(),
            password,
        ) {
            return internal_server_error(e);
        }
    }

    status(StatusCode::OK)
}

/// Sign out of an account
pub async fn sign_out_account<A, R, E>(
    req: Request<Incoming>,
    accounts: WebAccounts<A, R, E>,
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
        + From<sos_database::Error>
        + From<sos_account::Error>
        + From<std::io::Error>
        + Send
        + Sync
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
    accounts: WebAccounts<A, R, E>,
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
        + From<sos_database::Error>
        + From<sos_account::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    tracing::debug!("sign_out::all");
    sign_out(accounts, None).await
}

/// Sign out of an account
pub async fn sign_out<A, R, E>(
    accounts: WebAccounts<A, R, E>,
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
        + From<sos_database::Error>
        + From<sos_account::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    let mut user_accounts = accounts.as_ref().write().await;
    if let Some(account_id) = account_id {
        let Some(account) = user_accounts
            .iter_mut()
            .find(|a| a.address() == &account_id)
        else {
            return status(StatusCode::NOT_FOUND);
        };

        let folder_ids = if let Ok(folders) = account.list_folders().await {
            folders.into_iter().map(|f| *f.id()).collect::<Vec<_>>()
        } else {
            vec![]
        };

        match account.sign_out().await {
            Ok(_) => {
                if let Err(e) =
                    accounts.unwatch(&account_id, account.paths(), folder_ids)
                {
                    return internal_server_error(e);
                }
                status(StatusCode::OK)
            }
            Err(e) => internal_server_error(e),
        }
    } else {
        let mut account_info = Vec::new();
        for account in user_accounts.iter() {
            let folder_ids = if let Ok(folders) = account.list_folders().await
            {
                folders.into_iter().map(|f| *f.id()).collect::<Vec<_>>()
            } else {
                vec![]
            };

            account_info.push((
                *account.address(),
                account.paths(),
                folder_ids,
            ));
        }

        match user_accounts.sign_out_all().await {
            Ok(_) => {
                for (account_id, paths, folder_ids) in account_info {
                    if let Err(e) =
                        accounts.unwatch(&account_id, paths, folder_ids)
                    {
                        return internal_server_error(e);
                    }
                }
                status(StatusCode::OK)
            }
            Err(e) => internal_server_error(e),
        }
    }
}
