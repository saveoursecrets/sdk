use http::{header::CONTENT_TYPE, Request, Response, StatusCode};
use serde::Serialize;
use sos_net::sdk::prelude::MIME_TYPE_JSON;

use super::{Body, Incoming};

pub async fn json<S: Serialize>(
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

pub async fn internal_server_error(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    Ok(Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::default())
        .unwrap())
}

pub async fn forbidden(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    Ok(Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::default())
        .unwrap())
}

pub async fn not_found(
    _req: Request<Incoming>,
) -> hyper::Result<Response<Body>> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::default())
        .unwrap())
}
