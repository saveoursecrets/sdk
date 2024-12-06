use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::Service as HyperService;
use parking_lot::Mutex;
use sos_protocol::{
    constants::routes::v1::{
        ACCOUNTS_LIST, SYNC_ACCOUNT, SYNC_ACCOUNT_EVENTS, SYNC_ACCOUNT_STATUS,
    },
    Merge, SyncStorage,
};
use sos_sdk::prelude::{Account, AccountSwitcher};
use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};
use tokio::sync::RwLock;
use tower::service_fn;
use tower::util::BoxCloneService;
use tower::Service as _;

use crate::ServiceAppInfo;

// type Incoming = Vec<u8>;
type Body = Full<Bytes>;

// Need the Mutex as BoxCloneService does not implement Sync
type Service =
    Mutex<BoxCloneService<Request<Incoming>, Response<Body>, hyper::Error>>;

type Router = HashMap<Method, matchit::Router<Service>>;

mod account;
mod common;
mod events;

use account::*;
use common::*;
use events::*;

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
pub(crate) struct LocalServer {
    /// Service router.
    router: Arc<Router>,
}

impl LocalServer {
    /// Create a local server.
    pub fn new<A, R, E>(
        app_info: ServiceAppInfo,
        accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
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

        let state = accounts.clone();
        router
            .entry(Method::GET)
            .or_default()
            .insert(
                ACCOUNTS_LIST,
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
            .entry(Method::HEAD)
            .or_default()
            .insert(
                SYNC_ACCOUNT,
                BoxCloneService::new(service_fn(
                    move |req: Request<Incoming>| {
                        account_exists(req, state.clone())
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
                SYNC_ACCOUNT,
                BoxCloneService::new(service_fn(
                    move |req: Request<Incoming>| {
                        create_account(req, state.clone())
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
                SYNC_ACCOUNT,
                BoxCloneService::new(service_fn(
                    move |req: Request<Incoming>| {
                        update_account(req, state.clone())
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
                SYNC_ACCOUNT,
                BoxCloneService::new(service_fn(
                    move |req: Request<Incoming>| {
                        fetch_account(req, state.clone())
                    },
                ))
                .into(),
            )
            .unwrap();

        let state = accounts.clone();
        router
            .entry(Method::DELETE)
            .or_default()
            .insert(
                SYNC_ACCOUNT,
                BoxCloneService::new(service_fn(
                    move |req: Request<Incoming>| {
                        delete_account(req, state.clone())
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
                SYNC_ACCOUNT_STATUS,
                BoxCloneService::new(service_fn(
                    move |req: Request<Incoming>| {
                        sync_status(req, state.clone())
                    },
                ))
                .into(),
            )
            .unwrap();

        let state = accounts.clone();
        router
            .entry(Method::PATCH)
            .or_default()
            .insert(
                SYNC_ACCOUNT,
                BoxCloneService::new(service_fn(
                    move |req: Request<Incoming>| {
                        sync_account(req, state.clone())
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
                SYNC_ACCOUNT_EVENTS,
                BoxCloneService::new(service_fn(
                    move |req: Request<Incoming>| {
                        event_scan(req, state.clone())
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
                SYNC_ACCOUNT_EVENTS,
                BoxCloneService::new(service_fn(
                    move |req: Request<Incoming>| {
                        event_diff(req, state.clone())
                    },
                ))
                .into(),
            )
            .unwrap();

        let state = accounts.clone();
        router
            .entry(Method::PATCH)
            .or_default()
            .insert(
                SYNC_ACCOUNT_EVENTS,
                BoxCloneService::new(service_fn(
                    move |req: Request<Incoming>| {
                        event_patch(req, state.clone())
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

impl HyperService<Request<Incoming>> for LocalServer {
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
        Box::pin(async move { LocalServer::route(router, req).await })
    }
}
