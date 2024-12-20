use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::Service;
use notify::{
    recommended_watcher, Event, RecommendedWatcher, RecursiveMode, Watcher,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sos_protocol::{Merge, SyncStorage};
use sos_sdk::{
    events::{AccountEvent, EventLogExt, WriteEvent},
    prelude::{
        Account, AccountSwitcher, Address, Error as SdkError, ErrorExt, Paths,
    },
    vault::VaultId,
};
use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};
use tokio::sync::{broadcast, RwLock};
use tower::service_fn;
use tower::util::BoxCloneService;
use tower::Service as _;

use crate::{Error, FileEventError, Result, ServiceAppInfo};

type Body = Full<Bytes>;

// Need the Mutex as BoxCloneService does not implement Sync
type MethodRoute =
    Mutex<BoxCloneService<Request<Incoming>, Response<Body>, hyper::Error>>;

type Router = HashMap<Method, matchit::Router<MethodRoute>>;

/// Event broadcast when an account changes on disc.
#[typeshare::typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountChangeEvent {
    /// Account identifier.
    pub account_id: Address,
    /// Event records with information about the changes.
    pub records: ChangeRecords,
}

#[typeshare::typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "body")]
pub enum ChangeRecords {
    /// Account level events.
    Account(Vec<AccountEvent>),
    /// Folder level events.
    Folder(Vec<WriteEvent>),
}

/// User accounts for the web service.
pub struct WebAccounts<A, R, E>
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
    accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
    watchers: Arc<Mutex<HashMap<Address, RecommendedWatcher>>>,
    channel: broadcast::Sender<AccountChangeEvent>,
}

impl<A, R, E> Clone for WebAccounts<A, R, E>
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
    fn clone(&self) -> Self {
        Self {
            accounts: self.accounts.clone(),
            watchers: self.watchers.clone(),
            channel: self.channel.clone(),
        }
    }
}

impl<A, R, E> WebAccounts<A, R, E>
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
    /// Create new accounts.
    pub fn new(accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>) -> Self {
        let (tx, _) = broadcast::channel::<AccountChangeEvent>(64);
        Self {
            accounts,
            watchers: Arc::new(Mutex::new(HashMap::new())),
            channel: tx,
        }
    }

    /// Subscribe to change events.
    pub fn subscribe(&self) -> broadcast::Receiver<AccountChangeEvent> {
        self.channel.subscribe()
    }

    /// Start watching an account for changes.
    pub fn watch(
        &self,
        account_id: Address,
        paths: Arc<Paths>,
        folder_ids: Vec<VaultId>,
    ) -> Result<()> {
        let mut watchers = self.watchers.lock();
        let has_watcher = watchers.get(&account_id).is_some();
        if !has_watcher {
            let (tx, mut rx) = broadcast::channel::<Event>(32);
            let channel = self.channel.clone();
            let id = account_id.clone();
            let task_accounts = self.accounts.clone();
            tokio::task::spawn(async move {
                while let Ok(event) = rx.recv().await {
                    let path = event
                        .paths
                        .get(0)
                        .ok_or(FileEventError::NoEventPath)?;
                    let name = path.file_stem().ok_or(
                        FileEventError::EventPathStem(path.to_owned()),
                    )?;

                    // Get a diff of the events either for the
                    // account log or for a specific folder
                    let records = if name == "account" {
                        let accounts = task_accounts.read().await;
                        let account = accounts
                            .iter()
                            .find(|a| a.address() == &id)
                            .ok_or(FileEventError::NoAccount(id))?;

                        let storage = account.storage().await.unwrap();
                        let storage = storage.read().await;

                        let event_log = storage.account_log.read().await;
                        let commit = event_log.tree().last_commit();

                        let patch =
                            event_log.diff_events(commit.as_ref()).await?;
                        let records =
                            patch.into_events::<AccountEvent>().await?;

                        ChangeRecords::Account(records)
                    } else {
                        let folder_id: VaultId = name
                            .to_string_lossy()
                            .into_owned()
                            .parse()
                            .map_err(SdkError::from)?;

                        let accounts = task_accounts.read().await;
                        let account = accounts
                            .iter()
                            .find(|a| a.address() == &id)
                            .ok_or(FileEventError::NoAccount(id))?;

                        let storage = account.storage().await.unwrap();
                        let storage = storage.read().await;
                        let folder = storage
                            .cache()
                            .get(&folder_id)
                            .ok_or(FileEventError::NoFolder(folder_id))?;

                        let event_log = folder.event_log();
                        let event_log = event_log.read().await;
                        let commit = event_log.tree().last_commit();
                        let patch =
                            event_log.diff_events(commit.as_ref()).await?;
                        let records =
                            patch.into_events::<WriteEvent>().await?;

                        ChangeRecords::Folder(records)
                    };

                    let evt = AccountChangeEvent {
                        account_id: id.clone(),
                        records,
                    };
                    if let Err(e) = channel.send(evt) {
                        tracing::error!(error = ?e);
                    }
                }

                Ok::<_, Error>(())
            });

            let mut watcher =
                recommended_watcher(move |res: notify::Result<Event>| {
                    match res {
                        Ok(event) => {
                            if let Err(e) = tx.send(event) {
                                tracing::error!(error = %e);
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = %e);
                        }
                    }
                })?;

            watcher.watch(
                &paths.account_events(),
                RecursiveMode::NonRecursive,
            )?;

            for id in &folder_ids {
                watcher.watch(
                    &paths.event_log_path(id),
                    RecursiveMode::NonRecursive,
                )?;
            }
            watchers.insert(account_id, watcher);
        }
        Ok(())
    }

    /// Stop watching an account for changes.
    pub fn unwatch(
        &self,
        account_id: &Address,
        paths: Arc<Paths>,
        folder_ids: Vec<VaultId>,
    ) -> Result<bool> {
        let mut watchers = self.watchers.lock();
        if let Some(mut watcher) = watchers.remove(account_id) {
            watcher.unwatch(&paths.account_events())?;
            for id in &folder_ids {
                watcher.unwatch(&paths.event_log_path(id))?;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl<A, R, E> AsRef<Arc<RwLock<AccountSwitcher<A, R, E>>>>
    for WebAccounts<A, R, E>
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
    fn as_ref(&self) -> &Arc<RwLock<AccountSwitcher<A, R, E>>> {
        &self.accounts
    }
}

mod account;
mod common;
mod helpers;
mod search;
mod secret;

use account::*;
use common::*;
use helpers::*;
use search::*;
use secret::*;

async fn index(
    app_info: Arc<ServiceAppInfo>,
) -> hyper::Result<Response<Body>> {
    json(StatusCode::OK, &*app_info)
}

/// Local server handles sync requests from app integrations
/// running on the same device.
///
/// We avoid using axum directly as we need the `Sync` bound
/// but `axum::Body` is `!Sync`.
#[derive(Clone)]
pub(crate) struct LocalWebService {
    /// Service router.
    router: Arc<Router>,
}

impl LocalWebService {
    /// Create a local server.
    pub fn new<A, R, E>(
        app_info: ServiceAppInfo,
        accounts: WebAccounts<A, R, E>,
    ) -> Self
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
        let mut router = Router::new();
        let info = Arc::new(app_info);

        router
            .entry(Method::GET)
            .or_default()
            .insert(
                "/",
                BoxCloneService::new(service_fn(
                    move |_req: Request<Incoming>| index(info.clone()),
                ))
                .into(),
            )
            .unwrap();

        router
            .entry(Method::HEAD)
            .or_default()
            .insert(
                "/",
                BoxCloneService::new(service_fn(
                    move |_req: Request<Incoming>| async move {
                        status(StatusCode::OK)
                    },
                ))
                .into(),
            )
            .unwrap();

        router
            .entry(Method::GET)
            .or_default()
            .insert(
                "/open",
                BoxCloneService::new(service_fn(
                    move |req: Request<Incoming>| open_url(req),
                ))
                .into(),
            )
            .unwrap();

        // Route used to test chunking logic for responses
        // that exceed the 1MB native messaging API limit
        #[cfg(debug_assertions)]
        router
            .entry(Method::GET)
            .or_default()
            .insert(
                "/large-file",
                BoxCloneService::new(service_fn(
                    move |req: Request<Incoming>| large_file(req),
                ))
                .into(),
            )
            .unwrap();

        let state = accounts.clone();
        router
            .entry(Method::GET)
            .or_default()
            .insert(
                "/accounts",
                BoxCloneService::new(service_fn(
                    move |req: Request<Incoming>| {
                        list_accounts(req, state.clone())
                    },
                ))
                .into(),
            )
            .unwrap();

        let state = accounts.clone();
        router
            .entry(Method::GET)
            .or_default()
            .insert(
                "/accounts/authenticated",
                BoxCloneService::new(service_fn(
                    move |req: Request<Incoming>| {
                        authenticated_accounts(req, state.clone())
                    },
                ))
                .into(),
            )
            .unwrap();

        let state = accounts.clone();
        router
            .entry(Method::GET)
            .or_default()
            .insert(
                "/folders",
                BoxCloneService::new(service_fn(
                    move |req: Request<Incoming>| {
                        list_folders(req, state.clone())
                    },
                ))
                .into(),
            )
            .unwrap();

        let state = accounts.clone();
        router
            .entry(Method::POST)
            .or_default()
            .insert(
                "/search",
                BoxCloneService::new(service_fn(
                    move |req: Request<Incoming>| search(req, state.clone()),
                ))
                .into(),
            )
            .unwrap();

        let state = accounts.clone();
        router
            .entry(Method::POST)
            .or_default()
            .insert(
                "/search/view",
                BoxCloneService::new(service_fn(
                    move |req: Request<Incoming>| {
                        query_view(req, state.clone())
                    },
                ))
                .into(),
            )
            .unwrap();

        {
            let state = accounts.clone();
            router
                .entry(Method::POST)
                .or_default()
                .insert(
                    "/signin",
                    BoxCloneService::new(service_fn(
                        move |req: Request<Incoming>| {
                            sign_in(req, state.clone())
                        },
                    ))
                    .into(),
                )
                .unwrap();
        }

        let state = accounts.clone();
        router
            .entry(Method::PUT)
            .or_default()
            .insert(
                "/signin",
                BoxCloneService::new(service_fn(
                    move |req: Request<Incoming>| {
                        sign_in_account(req, state.clone())
                    },
                ))
                .into(),
            )
            .unwrap();

        {
            let state = accounts.clone();
            router
                .entry(Method::GET)
                .or_default()
                .insert(
                    "/secret",
                    BoxCloneService::new(service_fn(
                        move |req: Request<Incoming>| {
                            read_secret(req, state.clone())
                        },
                    ))
                    .into(),
                )
                .unwrap();
        }

        #[cfg(feature = "contacts")]
        {
            let state = accounts.clone();
            router
                .entry(Method::GET)
                .or_default()
                .insert(
                    "/avatar",
                    BoxCloneService::new(service_fn(
                        move |req: Request<Incoming>| {
                            load_avatar(req, state.clone())
                        },
                    ))
                    .into(),
                )
                .unwrap();
        }

        #[cfg(feature = "clipboard")]
        {
            let state = accounts.clone();
            router
                .entry(Method::POST)
                .or_default()
                .insert(
                    "/secret/copy",
                    BoxCloneService::new(service_fn(
                        move |req: Request<Incoming>| {
                            copy_secret_clipboard(req, state.clone())
                        },
                    ))
                    .into(),
                )
                .unwrap();
        }

        let state = accounts.clone();
        router
            .entry(Method::POST)
            .or_default()
            .insert(
                "/signout",
                BoxCloneService::new(service_fn(
                    move |req: Request<Incoming>| {
                        sign_out_account(req, state.clone())
                    },
                ))
                .into(),
            )
            .unwrap();

        let state = accounts.clone();
        router
            .entry(Method::PUT)
            .or_default()
            .insert(
                "/signout",
                BoxCloneService::new(service_fn(
                    move |req: Request<Incoming>| {
                        sign_out_all(req, state.clone())
                    },
                ))
                .into(),
            )
            .unwrap();

        Self {
            router: Arc::new(router),
        }
    }

    async fn route(
        router: Arc<Router>,
        req: Request<Incoming>,
    ) -> hyper::Result<Response<Body>> {
        let Some(router) = router.get(req.method()) else {
            return Ok(Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::default())
                .unwrap());
        };

        let Ok(found) = router.at(req.uri().path()) else {
            return not_found();
        };

        // lock the service for a very short time,
        // just to clone the service
        let mut service = found.value.lock().clone();
        match service.call(req).await {
            Ok(result) => Ok(result),
            Err(e) => internal_server_error(e),
        }
    }
}

impl Service<Request<Incoming>> for LocalWebService {
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = Pin<
        Box<
            dyn Future<
                    Output = std::result::Result<Self::Response, Self::Error>,
                > + Send,
        >,
    >;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let router = self.router.clone();
        Box::pin(async move { LocalWebService::route(router, req).await })
    }
}
