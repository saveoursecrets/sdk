//! Helper routes for utility functions.

use crate::web_service::{parse_query, status, Body, Incoming};
use http::{Request, Response, StatusCode};

/// Open a URL.
pub async fn open_url(
    req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    tracing::debug!(uri = %req.uri(), "open_url");

    let query = parse_query(req.uri());

    let Some(value) = query.get("url") else {
        return status(StatusCode::BAD_REQUEST);
    };

    tracing::debug!(url = %value, "open_url");

    #[cfg(debug_assertions)]
    if let Some(app) = option_env!("SOS_DEBUG_APP") {
        match open::with_detached(value, app) {
            Ok(_) => status(StatusCode::OK),
            Err(_) => status(StatusCode::BAD_GATEWAY),
        }
    } else {
        match open::that_detached(value) {
            Ok(_) => status(StatusCode::OK),
            Err(_) => status(StatusCode::BAD_GATEWAY),
        }
    }

    #[cfg(not(debug_assertions))]
    match open::that_detached(value) {
        Ok(_) => status(StatusCode::OK),
        Err(_) => status(StatusCode::BAD_GATEWAY),
    }
}

#[cfg(debug_assertions)]
pub async fn large_file(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    use bytes::Bytes;
    use http_body_util::Full;
    const MB: usize = 1024 * 1024;
    let body = [255u8; MB].to_vec();

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}
