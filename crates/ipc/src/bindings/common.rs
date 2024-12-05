include!(concat!(env!("OUT_DIR"), "/common.rs"));

use crate::{Error, Result};
use sos_net::protocol::local_transport::{LocalRequest, LocalResponse};
use std::collections::HashMap;

impl From<LocalRequest> for WireLocalRequest {
    fn from(value: LocalRequest) -> Self {
        WireLocalRequest {
            uri: value.uri.to_string(),
            method: value.method.to_string(),
            headers: value
                .headers
                .into_iter()
                .map(|(k, v)| WireTransportHeader { name: k, values: v })
                .collect(),
            body: value.body,
        }
    }
}

impl TryFrom<WireLocalRequest> for LocalRequest {
    type Error = Error;

    fn try_from(value: WireLocalRequest) -> Result<Self> {
        let mut headers = HashMap::new();
        for mut header in value.headers {
            let entry = headers.entry(header.name).or_insert(vec![]);
            entry.append(&mut header.values);
        }

        Ok(Self {
            uri: value.uri.parse()?,
            method: value.method.parse()?,
            headers,
            body: value.body,
        })
    }
}

impl From<LocalResponse> for WireLocalResponse {
    fn from(value: LocalResponse) -> Self {
        WireLocalResponse {
            status: value.status.into(),
            headers: value
                .headers
                .into_iter()
                .map(|(k, v)| WireTransportHeader { name: k, values: v })
                .collect(),
            body: value.body,
        }
    }
}

impl TryFrom<WireLocalResponse> for LocalResponse {
    type Error = Error;

    fn try_from(value: WireLocalResponse) -> Result<Self> {
        let mut headers = HashMap::new();
        for mut header in value.headers {
            let entry = headers.entry(header.name).or_insert(vec![]);
            entry.append(&mut header.values);
        }

        Ok(Self {
            status: value.status as u16,
            headers,
            body: value.body,
        })
    }
}
