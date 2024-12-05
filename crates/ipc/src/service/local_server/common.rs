use http::{
    header::{CONTENT_ENCODING, CONTENT_TYPE},
    Request, Response, StatusCode,
};
use serde::Serialize;
use sos_net::sdk::prelude::{
    Address, ENCODING_ZLIB, ENCODING_ZSTD, MIME_TYPE_JSON,
    MIME_TYPE_PROTOBUF, X_SOS_ACCOUNT_ID,
};

use super::{Body, Incoming};

#[derive(Serialize)]
struct ErrorReply {
    code: u16,
    message: String,
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

fn status(status: StatusCode) -> hyper::Result<Response<Body>> {
    Ok(Response::builder()
        .status(status)
        .body(Body::default())
        .unwrap())
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
        .body(body)
        .unwrap();
    Ok(response)
}

#[deprecated]
pub fn protobuf(body: Body) -> hyper::Result<Response<Body>> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF)
        .body(body)
        .unwrap())
}

pub fn protobuf_compress(body: Body) -> hyper::Result<Response<Body>> {
    use sos_net::protocol::compression::zlib;
    let Ok(buf) = zlib::encode_all(body.as_slice()) else {
        return internal_server_error("zlib::compress");
    };
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_ENCODING, ENCODING_ZLIB)
        .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF)
        .body(buf)
        .unwrap())
}

/*
pub fn protobuf_zstd(body: Body) -> hyper::Result<Response<Body>> {
    use sos_net::protocol::compression::zstd;
    let Ok(buf) = zstd::encode_all(body.as_slice(), 20) else {
        return internal_server_error("zstd::compress");
    };
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_ENCODING, ENCODING_ZSTD)
        .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF)
        .body(buf)
        .unwrap())
}
*/
