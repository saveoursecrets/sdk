use http::{Method, Request, Response, StatusCode};
use parking_lot::Mutex;
use sos_net::{
    protocol::{
        local_transport::{TransportRequest, TransportResponse},
        Merge, SyncStorage,
    },
    sdk::prelude::{
        routes::v1::{
            SYNC_ACCOUNT, SYNC_ACCOUNT_EVENTS, SYNC_ACCOUNT_STATUS,
        },
        Account, AccountSwitcher,
    },
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use tower::service_fn;
use tower::util::BoxCloneService;
use tower::Service as _;

use crate::ServiceAppInfo;

type Incoming = Vec<u8>;
type Body = Vec<u8>;

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
    json(&*app_info)
}

/// Local server handles sync requests from app integrations
/// running on the same device.
///
/// We avoid using axum directly as we need the `Sync` bound
/// but `axum::Body` is `!Sync`.
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
            + From<sos_net::sdk::Error>
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

    pub async fn handle(&self, req: TransportRequest) -> TransportResponse {
        let res = match req.try_into() {
            Ok(req) => self.call(req).await,
            Err(e) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(e.to_string().as_bytes().to_vec())
                .unwrap(),
        };
        res.into()
    }

    async fn call(&self, req: Request<Incoming>) -> Response<Body> {
        let router = self.router.clone();
        let result = Self::route(router, req).await.unwrap();
        result
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
        service.call(req).await
    }
}