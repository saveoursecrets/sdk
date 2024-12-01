use http::{Method, Request, Response, StatusCode};
use sos_net::{
    protocol::{TransportRequest, TransportResponse},
    sdk::prelude::{Account, AccountSwitcher},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::RwLock;
use tower::service_fn;
use tower::util::BoxCloneService;
use tower::Service as _;

type Incoming = Vec<u8>;
type Body = Vec<u8>;

// Need the Mutex as BoxCloneService does not implement Sync.
type Service =
    Mutex<BoxCloneService<Request<Incoming>, Response<Body>, hyper::Error>>;

type Router = HashMap<Method, matchit::Router<Service>>;

// GET /
async fn index(_req: Request<Incoming>) -> hyper::Result<Response<Body>> {
    Ok(Response::new(Body::from("Hello, world!")))
}

// 404 handler
async fn not_found(_req: Request<Incoming>) -> hyper::Result<Response<Body>> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::default())
        .unwrap())
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
    pub fn new(accounts: Arc<RwLock<AccountSwitcher<E, R, A>>>) -> Self {
        let mut router = Router::new();

        // GET / => `index`
        router
            .entry(Method::GET)
            .or_default()
            .insert("/", BoxCloneService::new(service_fn(index)).into())
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

        // lock the service for a very short time, just to clone the service
        let mut service = found.value.lock().unwrap().clone();
        service.call(req).await
    }
}
