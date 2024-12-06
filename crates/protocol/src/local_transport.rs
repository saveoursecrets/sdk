//! Types used for communicating between apps on the same device.

use crate::{
    constants::{ENCODING_ZLIB, MIME_TYPE_JSON, X_SOS_REQUEST_ID},
    Error, Result,
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
    /// Extract a request id.
    ///
    /// If no header is present or the value is invalid zero
    /// is returned.
    pub fn request_id(&self) -> u64 {
        if let Some(values) = self.headers.get(X_SOS_REQUEST_ID) {
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

    /// Duration allowed for a request.
    pub fn timeout_duration(&self) -> Duration {
        Duration::from_secs(15)
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

/*
impl Default for LocalResponse {
    fn default() -> Self {
        Self {
            status: StatusCode::OK.into(),
            headers: Default::default(),
            body: Default::default(),
        }
    }
}
*/

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

impl LocalResponse {
    /// Internal error response.
    pub fn new_error(status: StatusCode, _e: impl std::error::Error) -> Self {
        Self {
            status: status.into(),
            headers: Default::default(),
            body: Default::default(),
        }
    }

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

    /// Extract a request id.
    ///
    /// If no header is present or the value is invalid zero
    /// is returned.
    pub fn request_id(&self) -> u64 {
        if let Some(values) = self.headers.get(X_SOS_REQUEST_ID) {
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
    pub fn set_request_id(&mut self, id: u64) {
        self.headers
            .insert(X_SOS_REQUEST_ID.to_owned(), vec![id.to_string()]);
    }

    /// Extract a content type header.
    pub fn content_type(&self) -> Option<&str> {
        if let Some(values) = self.headers.get(CONTENT_TYPE.as_str()) {
            values.first().map(|v| v.as_str())
        } else {
            None
        }
    }

    /// Determine if this response is JSON.
    pub fn is_json(&self) -> bool {
        if let Some(values) = self.headers.get(CONTENT_TYPE.as_str()) {
            values
                .iter()
                .find(|v| v.as_str() == MIME_TYPE_JSON)
                .is_some()
        } else {
            false
        }
    }

    /// Decompress the response body.
    pub fn decompress(&mut self) -> Result<()> {
        if self.is_zlib() {
            println!("decompress: {}", self.body.len());
            self.body =
                crate::compression::zlib::decode_all(self.body.as_slice())?;
            println!("inflated : {}", self.body.len());
        }
        Ok(())
    }

    /// Determine if this response is using Zlib content encoding.
    pub fn is_zlib(&self) -> bool {
        if let Some(values) = self.headers.get(CONTENT_ENCODING.as_str()) {
            values
                .iter()
                .find(|v| v.as_str() == ENCODING_ZLIB)
                .is_some()
        } else {
            false
        }
    }

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
    pub fn bytes(self) -> Bytes {
        self.body.into()
    }
}

/// Generic local transport.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait LocalTransport {
    /// Send a request over the local transport.
    async fn call(&mut self, request: LocalRequest) -> LocalResponse;
}
