use http::{header::CONTENT_TYPE, Request, Response, StatusCode};
use serde::Serialize;
use sos_net::sdk::prelude::{
    Address, MIME_TYPE_JSON, MIME_TYPE_PROTOBUF, X_SOS_ACCOUNT_ID,
};

use super::{Body, Incoming};

pub fn parse_account_id(req: &Request<Incoming>) -> Option<Address> {
    let Some(Ok(account_id)) =
        req.headers().get(X_SOS_ACCOUNT_ID).map(|v| v.to_str())
    else {
        return None;
    };
    let Ok(account_id) = account_id.parse::<Address>() else {
        return None;
    };
    Some(account_id)
}

fn status(status: StatusCode) -> hyper::Result<Response<Body>> {
    Ok(Response::builder()
        .status(status)
        .body(Body::default())
        .unwrap())
}

pub fn internal_server_error() -> hyper::Result<Response<Body>> {
    status(StatusCode::INTERNAL_SERVER_ERROR)
}

pub fn bad_request() -> hyper::Result<Response<Body>> {
    status(StatusCode::BAD_REQUEST)
}

pub fn forbidden() -> hyper::Result<Response<Body>> {
    status(StatusCode::FORBIDDEN)
}

pub fn not_found() -> hyper::Result<Response<Body>> {
    status(StatusCode::NOT_FOUND)
}

pub fn ok(body: Body) -> hyper::Result<Response<Body>> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(body)
        .unwrap())
}

pub fn json<S: Serialize>(value: &S) -> hyper::Result<Response<Body>> {
    let Ok(body) = serde_json::to_vec(value) else {
        return internal_server_error();
    };
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, MIME_TYPE_JSON)
        .body(body)
        .unwrap();
    Ok(response)
}

pub fn protobuf(body: Body) -> hyper::Result<Response<Body>> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF)
        .body(body)
        .unwrap())
}
