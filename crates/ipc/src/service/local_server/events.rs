use http::{Request, Response};

use super::{Body, Incoming};

pub async fn events_scan(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    todo!();
}

pub async fn events_diff(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    todo!();
}

pub async fn events_patch(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    todo!();
}
