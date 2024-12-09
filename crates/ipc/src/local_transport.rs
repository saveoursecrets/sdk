//! Types used for HTTP communication between apps
//! on the same device.
//!
//! Wraps the `http` request and response types so we can
//! serialize and deserialize from JSON for transfer via
//! the browser native messaging API.
//!
//! Browsers limit each length-prefixed JSON encoded message
//! to 1MB so these types provide functions to split a message
//! into chunks.

use crate::{Error, Result};

use sos_protocol::constants::{MIME_TYPE_JSON, X_SOS_REQUEST_ID};

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

    /// Mutable message body.
    fn body_mut(&mut self) -> &mut Vec<u8>;

    /// Consume the message body.
    fn into_body(self) -> Vec<u8>;

    /// Number of chunks.
    fn chunks_len(&self) -> u32;

    /// Zero-based chunk index of this message.
    fn chunk_index(&self) -> u32;

    /// Convert this message into a collection of chunks.
    ///
    /// If the size of the body is less than limit then
    /// only this message is included.
    ///
    /// Conversion is performed on the number of bytes in the
    /// body but the native messaging API restricts the serialized
    /// JSON to 1MB so it's wise to choose a value smaller
    /// than the 1MB limit so there is some headroom for the JSON
    /// serialization overhead.
    fn into_chunks(self, limit: usize, chunk_size: usize) -> Vec<Self>
    where
        Self: Sized;

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

    /// Convert the message into parts.
    fn into_parts(mut self) -> (Headers, Vec<u8>)
    where
        Self: Sized,
    {
        let headers =
            std::mem::replace(self.headers_mut(), Default::default());
        (headers, self.into_body())
    }

    /// Convert the body to bytes.
    fn bytes(self) -> Bytes
    where
        Self: Sized,
    {
        self.into_body().into()
    }

    /// Convert from a collection of chunks into a response.
    ///
    /// # Panics
    ///
    /// If chunks is empty.
    fn from_chunks(mut chunks: Vec<Self>) -> Self
    where
        Self: Sized,
    {
        chunks.sort_by(|a, b| a.chunk_index().cmp(&b.chunk_index()));
        let mut it = chunks.into_iter();
        let mut message = it.next().expect("to have one chunk");
        for chunk in it {
            let mut body = chunk.into_body();
            message.body_mut().append(&mut body);
        }
        message
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
#[serde(default, rename_all = "camelCase")]
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
    pub headers: Headers,
    /// Request body.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body: Vec<u8>,
    /// Number of chunks for this message.
    pub chunks_length: u32,
    /// Chunk index for this message.
    pub chunk_index: u32,
}

impl Default for LocalRequest {
    fn default() -> Self {
        Self {
            method: Method::GET,
            uri: Uri::builder().path_and_query("/").build().unwrap(),
            headers: Default::default(),
            body: Default::default(),
            chunks_length: 1,
            chunk_index: 0,
        }
    }
}

impl LocalRequest {
    /// Create a GET request from a URI.
    pub fn get(uri: Uri) -> Self {
        Self {
            method: Method::GET,
            uri,
            headers: Default::default(),
            body: Default::default(),
            chunks_length: 1,
            chunk_index: 0,
        }
    }

    /// Create a HEAD request from a URI.
    pub fn head(uri: Uri) -> Self {
        Self {
            method: Method::HEAD,
            uri,
            headers: Default::default(),
            body: Default::default(),
            chunks_length: 1,
            chunk_index: 0,
        }
    }

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

    fn body_mut(&mut self) -> &mut Vec<u8> {
        &mut self.body
    }

    fn into_body(self) -> Vec<u8> {
        self.body
    }

    fn chunks_len(&self) -> u32 {
        self.chunks_length
    }

    fn chunk_index(&self) -> u32 {
        self.chunk_index
    }

    fn into_chunks(self, limit: usize, chunk_size: usize) -> Vec<Self> {
        if self.body.len() < limit {
            vec![self]
        } else {
            let mut messages = Vec::new();
            let uri = self.uri.clone();
            let method = self.method.clone();
            let (headers, body) = self.into_parts();
            let len = if body.len() > chunk_size {
                let mut len = body.len() / chunk_size;
                if body.len() % chunk_size != 0 {
                    len += 1;
                }
                len
            } else {
                1
            };
            for (index, window) in
                body.as_slice().chunks(chunk_size).enumerate()
            {
                let message = Self {
                    uri: uri.clone(),
                    method: method.clone(),
                    body: window.to_owned(),
                    headers: headers.clone(),
                    chunks_length: len as u32,
                    chunk_index: index as u32,
                };
                messages.push(message);
            }
            messages
        }
    }
}

impl fmt::Debug for LocalRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalRequest")
            .field("method", &self.method.to_string())
            .field("uri", &self.uri.to_string())
            .field("headers", &format_args!("{:?}", self.headers))
            .field("body_length", &self.body.len().to_string())
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
            chunks_length: 1,
            chunk_index: 0,
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
#[serde(rename_all = "camelCase")]
pub struct LocalResponse {
    /// Response status code.
    pub status: u16,
    /// Response headers.
    #[serde_as(as = "Vec<(_, _)>")]
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: Headers,
    /// Response body.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body: Vec<u8>,
    /// Number of chunks for this message.
    pub chunks_length: u32,
    /// Chunk index for this message.
    pub chunk_index: u32,
}

impl Default for LocalResponse {
    fn default() -> Self {
        Self {
            status: StatusCode::OK.into(),
            headers: Default::default(),
            body: Default::default(),
            chunks_length: 1,
            chunk_index: 0,
        }
    }
}

impl fmt::Debug for LocalResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalResponse")
            .field("status", &self.status.to_string())
            .field("headers", &format_args!("{:?}", self.headers))
            .field("body_length", &self.body.len().to_string())
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
            chunks_length: 1,
            chunk_index: 0,
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
            chunks_length: 1,
            chunk_index: 0,
        };
        res.set_request_id(id);
        res
    }

    /// Status code.
    pub fn status(&self) -> Result<StatusCode> {
        Ok(self.status.try_into()?)
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

    fn body_mut(&mut self) -> &mut Vec<u8> {
        &mut self.body
    }

    fn into_body(self) -> Vec<u8> {
        self.body
    }

    fn chunks_len(&self) -> u32 {
        self.chunks_length
    }

    fn chunk_index(&self) -> u32 {
        self.chunk_index
    }

    fn into_chunks(self, limit: usize, chunk_size: usize) -> Vec<Self> {
        if self.body.len() < limit {
            vec![self]
        } else {
            let mut messages = Vec::new();
            let status = self.status.clone();
            let (headers, body) = self.into_parts();
            let len = if body.len() > chunk_size {
                let mut len = body.len() / chunk_size;
                if body.len() % chunk_size != 0 {
                    len += 1;
                }
                len
            } else {
                1
            };
            for (index, window) in
                body.as_slice().chunks(chunk_size).enumerate()
            {
                let message = Self {
                    status,
                    headers: headers.clone(),
                    body: window.to_owned(),
                    chunks_length: len as u32,
                    chunk_index: index as u32,
                };
                messages.push(message);
            }
            messages
        }
    }
}
