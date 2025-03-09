use super::{Body, Incoming};
use bytes::Bytes;
use http::{header::CONTENT_TYPE, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use serde::{de::DeserializeOwned, Serialize};
use sos_core::AccountId;
use sos_protocol::{
    constants::{MIME_TYPE_JSON, X_SOS_ACCOUNT_ID},
    ErrorReply,
};
use std::collections::HashMap;
use url::form_urlencoded;

pub async fn parse_json_body<T: DeserializeOwned>(
    req: Request<Incoming>,
) -> crate::Result<T> {
    let bytes = read_bytes(req).await?.to_vec();
    Ok(serde_json::from_slice::<T>(&bytes)?)
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

pub fn parse_account_id(req: &Request<Incoming>) -> Option<AccountId> {
    let Some(Ok(account_id)) =
        req.headers().get(X_SOS_ACCOUNT_ID).map(|v| v.to_str())
    else {
        return None;
    };
    let Ok(account_id) = account_id.parse::<AccountId>() else {
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
    let error = ErrorReply::new_message(StatusCode::INTERNAL_SERVER_ERROR, e);
    json(StatusCode::INTERNAL_SERVER_ERROR, &error)
}

pub fn json<S: Serialize>(
    status: StatusCode,
    value: &S,
) -> hyper::Result<Response<Body>> {
    match serde_json::to_vec(value) {
        Ok(body) => {
            let response = Response::builder()
                .status(status)
                .header(CONTENT_TYPE, MIME_TYPE_JSON)
                .body(Full::new(Bytes::from(body)))
                .unwrap();
            Ok(response)
        }
        Err(e) => internal_server_error(e),
    }
}

pub fn text(
    status: StatusCode,
    body: String,
) -> hyper::Result<Response<Body>> {
    let response = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain")
        .body(Full::new(Bytes::from(body.as_bytes().to_vec())))
        .unwrap();
    Ok(response)
}
