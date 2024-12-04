//! Types used for communicating between apps on the same device.

use crate::{Error, Result};
use async_trait::async_trait;
use bytes::Bytes;
use http::{
    header::CONTENT_TYPE, Method, Request, Response, StatusCode, Uri,
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use sos_sdk::constants::MIME_TYPE_JSON;
use std::collections::HashMap;

/// Request that can be sent to a local data source.
///
/// Supports serde so this type is compatible with the
/// browser extension which transfers JSON via the
/// native messaging API.
///
/// The body will usually be protobuf-encoded binary data.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportRequest {
    /// Request method.
    #[serde_as(as = "DisplayFromStr")]
    pub method: Method,
    /// Request URL.
    #[serde_as(as = "DisplayFromStr")]
    pub uri: Uri,
    /// Request headers.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, Vec<String>>,
    /// Request body.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub body: Vec<u8>,
}

impl From<Request<Vec<u8>>> for TransportRequest {
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

impl TryFrom<TransportRequest> for Request<Vec<u8>> {
    type Error = Error;

    fn try_from(value: TransportRequest) -> Result<Self> {
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
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct TransportResponse {
    /// Response status code.
    #[serde_as(as = "DisplayFromStr")]
    pub status: StatusCode,
    /// Response headers.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, Vec<String>>,
    /// Response body.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub body: Vec<u8>,
}

impl From<Response<Vec<u8>>> for TransportResponse {
    fn from(value: Response<Vec<u8>>) -> Self {
        let (parts, body) = value.into_parts();

        let mut headers = HashMap::new();
        for (key, value) in parts.headers.iter() {
            let entry = headers.entry(key.to_string()).or_insert(vec![]);
            entry.push(value.to_str().unwrap().to_owned());
        }

        Self {
            status: parts.status,
            headers,
            body,
        }
    }
}

impl TransportResponse {
    /// Status code.
    pub fn status(&self) -> StatusCode {
        self.status
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

    /// Convert the body to bytes.
    pub fn bytes(self) -> Bytes {
        self.body.into()
    }
}

/// Generic local transport.
#[async_trait]
pub trait LocalTransport {
    /// Send a request over the local transport.
    async fn call(
        &mut self,
        request: TransportRequest,
    ) -> Result<TransportResponse>;
}