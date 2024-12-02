use http::{Request, Response};

use super::{Body, Incoming};

pub async fn account_exists(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    todo!();
}

pub async fn create_account(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    todo!();
}

pub async fn update_account(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    todo!();
}

pub async fn fetch_account(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    todo!();
}

pub async fn account_status(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    todo!();
}

pub async fn sync_account(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    todo!();
}
