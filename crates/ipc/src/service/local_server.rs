use http::{header::CONTENT_TYPE, Method, Request, Response, StatusCode};
use parking_lot::Mutex;
use serde::Serialize;
use sos_net::{
    protocol::{TransportRequest, TransportResponse},
    sdk::prelude::{
        routes::v1::{
            SYNC_ACCOUNT, SYNC_ACCOUNT_EVENTS, SYNC_ACCOUNT_STATUS,
        },
        Account, AccountSwitcher, MIME_TYPE_JSON,
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

async fn json<S: Serialize>(
    req: Request<Incoming>,
    value: &S,
) -> hyper::Result<Response<Body>> {
    let Ok(body) = serde_json::to_vec(value) else {
        return internal_server_error(req).await;
    };
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, MIME_TYPE_JSON)
        .body(body)
        .unwrap();
    Ok(response)
}

async fn index(
    req: Request<Incoming>,
    app_info: Arc<ServiceAppInfo>,
) -> hyper::Result<Response<Body>> {
    json(req, &*app_info).await
}

async fn internal_server_error(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    Ok(Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::default())
        .unwrap())
}

async fn forbidden(_req: Request<Incoming>) -> hyper::Result<Response<Body>> {
    Ok(Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::default())
        .unwrap())
}

async fn not_found(_req: Request<Incoming>) -> hyper::Result<Response<Body>> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::default())
        .unwrap())
}

async fn account_exists(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    todo!();
}

async fn create_account(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    todo!();
}

async fn update_account(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    todo!();
}

async fn fetch_account(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    todo!();
}

async fn account_status(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    todo!();
}

async fn sync_account(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    todo!();
}

async fn events_scan(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    todo!();
}

async fn events_diff(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    todo!();
}

async fn events_patch(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    todo!();
}

/// Local server handles sync requests from app integrations
/// running on the same device.
///
/// We avoid using axum directly as we need the `Sync` bound
/// but `axum::Body` is `!Sync`.
pub(crate) struct LocalServer<E, R, A>
where
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
    R: 'static,
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
{
    /// Collection of accounts.
    accounts: Arc<RwLock<AccountSwitcher<E, R, A>>>,
    /// Service router.
    router: Arc<Router>,
}

impl<E, R, A> LocalServer<E, R, A>
where
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
    R: 'static,
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
{
    /// Create a local server.
    pub fn new(
        app_info: ServiceAppInfo,
        accounts: Arc<RwLock<AccountSwitcher<E, R, A>>>,
    ) -> Self {
        let mut router = Router::new();
        let info = Arc::new(app_info);

        router
            .entry(Method::GET)
            .or_default()
            .insert(
                "/",
                BoxCloneService::new(service_fn(
                    move |req: Request<Incoming>| index(req, info.clone()),
                ))
                .into(),
            )
            .unwrap();

        router
            .entry(Method::HEAD)
            .or_default()
            .insert(
                format!("/{}", SYNC_ACCOUNT),
                BoxCloneService::new(service_fn(account_exists)).into(),
            )
            .unwrap();

        router
            .entry(Method::PUT)
            .or_default()
            .insert(
                format!("/{}", SYNC_ACCOUNT),
                BoxCloneService::new(service_fn(create_account)).into(),
            )
            .unwrap();

        router
            .entry(Method::POST)
            .or_default()
            .insert(
                format!("/{}", SYNC_ACCOUNT),
                BoxCloneService::new(service_fn(update_account)).into(),
            )
            .unwrap();

        router
            .entry(Method::GET)
            .or_default()
            .insert(
                format!("/{}", SYNC_ACCOUNT),
                BoxCloneService::new(service_fn(fetch_account)).into(),
            )
            .unwrap();

        // Don't allow deleting accounts on the local server.
        //
        // If the user really wants to do that they can use the
        // primary app and not an app integration.
        router
            .entry(Method::DELETE)
            .or_default()
            .insert(
                format!("/{}", SYNC_ACCOUNT),
                BoxCloneService::new(service_fn(forbidden)).into(),
            )
            .unwrap();

        router
            .entry(Method::GET)
            .or_default()
            .insert(
                format!("/{}", SYNC_ACCOUNT_STATUS),
                BoxCloneService::new(service_fn(account_status)).into(),
            )
            .unwrap();

        router
            .entry(Method::PATCH)
            .or_default()
            .insert(
                format!("/{}", SYNC_ACCOUNT),
                BoxCloneService::new(service_fn(sync_account)).into(),
            )
            .unwrap();

        router
            .entry(Method::GET)
            .or_default()
            .insert(
                format!("/{}", SYNC_ACCOUNT_EVENTS),
                BoxCloneService::new(service_fn(events_scan)).into(),
            )
            .unwrap();

        router
            .entry(Method::POST)
            .or_default()
            .insert(
                format!("/{}", SYNC_ACCOUNT_EVENTS),
                BoxCloneService::new(service_fn(events_diff)).into(),
            )
            .unwrap();

        router
            .entry(Method::PATCH)
            .or_default()
            .insert(
                format!("/{}", SYNC_ACCOUNT_EVENTS),
                BoxCloneService::new(service_fn(events_patch)).into(),
            )
            .unwrap();

        Self {
            accounts,
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
            return not_found(req).await;
        };

        // lock the service for a very short time,
        // just to clone the service
        let mut service = found.value.lock().clone();
        service.call(req).await
    }
}
