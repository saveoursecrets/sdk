use std::collections::HashMap;

use bytes::Bytes;
use http::{header::CONTENT_TYPE, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use serde::Serialize;
use sos_protocol::constants::{MIME_TYPE_JSON, X_SOS_ACCOUNT_ID};
use sos_sdk::{prelude::Address, url::form_urlencoded};

use super::{Body, Incoming};

#[derive(Serialize)]
struct ErrorReply {
    code: u16,
    message: String,
}

pub fn parse_query(uri: &Uri) -> HashMap<String, String> {
    let uri = uri.to_string();
    let parts = uri.splitn(2, "?");
    let Some(query) = parts.last() else {
        return Default::default();
    };
    let it = form_urlencoded::parse(query.as_bytes());
    it.map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect::<HashMap<_, _>>()
}

pub async fn read_bytes(req: Request<Incoming>) -> hyper::Result<Bytes> {
    Ok(req.collect().await?.to_bytes())
}

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

pub fn status(status: StatusCode) -> hyper::Result<Response<Body>> {
    Ok(Response::builder()
        .status(status)
        .body(Body::default())
        .unwrap())
}

pub fn not_found() -> hyper::Result<Response<Body>> {
    status(StatusCode::NOT_FOUND)
}

pub fn internal_server_error(
    e: impl std::fmt::Display,
) -> hyper::Result<Response<Body>> {
    let error = ErrorReply {
        code: StatusCode::INTERNAL_SERVER_ERROR.into(),
        message: e.to_string(),
    };
    json(StatusCode::INTERNAL_SERVER_ERROR, &error)
}

pub fn json<S: Serialize>(
    status: StatusCode,
    value: &S,
) -> hyper::Result<Response<Body>> {
    let Ok(body) = serde_json::to_vec(value) else {
        return Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::default())
            .unwrap());
    };
    let response = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, MIME_TYPE_JSON)
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    Ok(response)
}
