//! Types used for communicating between apps on the same device.

use crate::{Error, Result};

use sos_protocol::constants::{
    ENCODING_ZLIB, MIME_TYPE_JSON, X_SOS_REQUEST_ID,
};

use async_trait::async_trait;
use bytes::Bytes;
use http::{
    header::{CONTENT_ENCODING, CONTENT_TYPE},
    Method, Request, Response, StatusCode, Uri,
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::{collections::HashMap, fmt, time::Duration};
use typeshare::typeshare;

/// Generic local transport.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait LocalTransport {
    /// Send a request over the local transport.
    async fn call(&mut self, request: LocalRequest) -> LocalResponse;
}

/// HTTP headers encoded as strings.
pub type Headers = HashMap<String, Vec<String>>;

/// Trait for requests and responses.
pub trait HttpMessage {
    /// Message headers.
    fn headers(&self) -> &Headers;

    /// Mutable message headers.
    fn headers_mut(&mut self) -> &mut Headers;

    /// Message body.
    fn body(&self) -> &[u8];

    /// Consume the message body.
    fn into_body(self) -> Vec<u8>;

    /// Extract a request id.
    ///
    /// If no header is present or the value is invalid zero
    /// is returned.
    fn request_id(&self) -> u64 {
        if let Some(values) = self.headers().get(X_SOS_REQUEST_ID) {
            if let Some(value) = values.first().map(|v| v.as_str()) {
                let Ok(id) = value.parse::<u64>() else {
                    return 0;
                };
                id
            } else {
                0
            }
        } else {
            0
        }
    }

    /// Set a request id.
    fn set_request_id(&mut self, id: u64) {
        self.headers_mut()
            .insert(X_SOS_REQUEST_ID.to_owned(), vec![id.to_string()]);
    }

    /// Read a content type header.
    fn content_type(&self) -> Option<&str> {
        if let Some(values) = self.headers().get(CONTENT_TYPE.as_str()) {
            values.first().map(|v| v.as_str())
        } else {
            None
        }
    }

    /// Read a content encoding header.
    fn content_encoding(&self) -> Option<&str> {
        if let Some(values) = self.headers().get(CONTENT_ENCODING.as_str()) {
            values.first().map(|v| v.as_str())
        } else {
            None
        }
    }

    /// Determine if this message is JSON.
    fn is_json(&self) -> bool {
        let Some(value) = self.content_type() else {
            return false;
        };
        value == MIME_TYPE_JSON
    }

    /// Determine if this message is Zlib content encoding.
    fn is_zlib(&self) -> bool {
        let Some(value) = self.content_encoding() else {
            return false;
        };
        value == ENCODING_ZLIB
    }

    /*
    /// Set JSON content type.
    fn set_json(&mut self) {
        self.headers_mut().insert(
            CONTENT_TYPE.to_string(),
            vec![MIME_TYPE_JSON.to_string()],
        );
    }
    */

    /*
    /// Determine if this response is using Zstd content encoding.
    pub fn is_zstd(&self) -> bool {
        if let Some(values) = self.headers.get(CONTENT_ENCODING.as_str()) {
            values
                .iter()
                .find(|v| v.as_str() == ENCODING_ZSTD)
                .is_some()
        } else {
            false
        }
    }
    */

    /// Convert the body to bytes.
    fn bytes(self) -> Bytes
    where
        Self: Sized,
    {
        self.into_body().into()
    }
}

/// Request that can be sent to a local data source.
///
/// Supports serde so this type is compatible with the
/// browser extension which transfers JSON via the
/// native messaging API.
///
/// The body will usually be protobuf-encoded binary data.
#[typeshare]
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct LocalRequest {
    /// Request method.
    #[serde_as(as = "DisplayFromStr")]
    pub method: Method,
    /// Request URL.
    #[serde_as(as = "DisplayFromStr")]
    pub uri: Uri,
    /// Request headers.
    #[serde_as(as = "Vec<(_, _)>")]
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, Vec<String>>,
    /// Request body.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body: Vec<u8>,
}

impl Default for LocalRequest {
    fn default() -> Self {
        Self {
            method: Method::GET,
            uri: Uri::builder().path_and_query("/").build().unwrap(),
            headers: Default::default(),
            body: Default::default(),
        }
    }
}

impl LocalRequest {
    /// Duration allowed for a request.
    pub fn timeout_duration(&self) -> Duration {
        Duration::from_secs(15)
    }
}

impl HttpMessage for LocalRequest {
    fn headers(&self) -> &Headers {
        &self.headers
    }

    fn headers_mut(&mut self) -> &mut Headers {
        &mut self.headers
    }

    fn body(&self) -> &[u8] {
        self.body.as_slice()
    }

    fn into_body(self) -> Vec<u8> {
        self.body
    }
}

impl fmt::Debug for LocalRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalRequest")
            .field("method", &self.method.to_string())
            .field("uri", &self.uri.to_string())
            .field("headers", &format_args!("{:?}", self.headers))
            .field("body", &self.body.len().to_string())
            .finish()
    }
}

impl From<Request<Vec<u8>>> for LocalRequest {
    fn from(value: Request<Vec<u8>>) -> Self {
        let (parts, body) = value.into_parts();

        let mut headers = HashMap::new();
        for (key, value) in parts.headers.iter() {
            let entry = headers.entry(key.to_string()).or_insert(vec![]);
            entry.push(value.to_str().unwrap().to_owned());
        }

        Self {
            method: parts.method,
            uri: parts.uri,
            headers,
            body,
        }
    }
}

impl TryFrom<LocalRequest> for Request<Vec<u8>> {
    type Error = Error;

    fn try_from(value: LocalRequest) -> Result<Self> {
        let mut request =
            Request::builder().uri(&value.uri).method(&value.method);
        for (k, values) in &value.headers {
            for value in values {
                request = request.header(k, value);
            }
        }
        Ok(request.body(value.body)?)
    }
}

/// Response received from a local data source.
///
/// Supports serde so this type is compatible with the
/// browser extension which transfers JSON via the
/// native messaging API.
///
/// The body will usually be protobuf-encoded binary data.
#[typeshare]
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct LocalResponse {
    /// Response status code.
    pub status: u16,
    /// Response headers.
    #[serde_as(as = "Vec<(_, _)>")]
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, Vec<String>>,
    /// Response body.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body: Vec<u8>,
}

impl Default for LocalResponse {
    fn default() -> Self {
        Self {
            status: StatusCode::OK.into(),
            headers: Default::default(),
            body: Default::default(),
        }
    }
}

impl fmt::Debug for LocalResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalResponse")
            .field("status", &self.status.to_string())
            .field("headers", &format_args!("{:?}", self.headers))
            .field("body", &self.body.len().to_string())
            .finish()
    }
}

impl From<Response<Vec<u8>>> for LocalResponse {
    fn from(value: Response<Vec<u8>>) -> Self {
        let (parts, body) = value.into_parts();

        let mut headers = HashMap::new();
        for (key, value) in parts.headers.iter() {
            let entry = headers.entry(key.to_string()).or_insert(vec![]);
            entry.push(value.to_str().unwrap().to_owned());
        }

        Self {
            status: parts.status.into(),
            headers,
            body,
        }
    }
}

impl From<StatusCode> for LocalResponse {
    fn from(status: StatusCode) -> Self {
        Self {
            status: status.into(),
            ..Default::default()
        }
    }
}

impl LocalResponse {
    /// Create a response with a request id.
    pub fn with_id(status: StatusCode, id: u64) -> Self {
        let mut res = Self {
            status: status.into(),
            headers: Default::default(),
            body: Default::default(),
        };
        res.set_request_id(id);
        res
    }

    /// Status code.
    pub fn status(&self) -> Result<StatusCode> {
        Ok(self.status.try_into()?)
    }

    /// Decompress the response body.
    pub fn decompress(&mut self) -> Result<()> {
        if self.is_zlib() {
            self.body =
                crate::compression::zlib::decode_all(self.body.as_slice())?;
        }
        Ok(())
    }
}

impl HttpMessage for LocalResponse {
    fn headers(&self) -> &Headers {
        &self.headers
    }

    fn headers_mut(&mut self) -> &mut Headers {
        &mut self.headers
    }

    fn body(&self) -> &[u8] {
        self.body.as_slice()
    }

    fn into_body(self) -> Vec<u8> {
        self.body
    }
}
