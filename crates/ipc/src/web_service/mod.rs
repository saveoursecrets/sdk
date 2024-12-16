use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::Service;
use parking_lot::Mutex;
use sos_protocol::{Merge, SyncStorage};
use sos_sdk::prelude::{Account, AccountSwitcher, ErrorExt};
use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};
use tokio::sync::RwLock;
use tower::service_fn;
use tower::util::BoxCloneService;
use tower::Service as _;

use crate::ServiceAppInfo;

type Body = Full<Bytes>;

// Need the Mutex as BoxCloneService does not implement Sync
type MethodRoute =
    Mutex<BoxCloneService<Request<Incoming>, Response<Body>, hyper::Error>>;

type Router = HashMap<Method, matchit::Router<MethodRoute>>;

type Accounts<A, R, E> = Arc<RwLock<AccountSwitcher<A, R, E>>>;

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
        accounts: Accounts<A, R, E>,
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
