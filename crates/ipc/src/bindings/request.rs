include!(concat!(env!("OUT_DIR"), "/request.rs"));

use crate::{Error, Result, WireVoidBody};
use serde::{Deserialize, Serialize};
use sos_net::{
    protocol::local_transport::LocalRequest,
    sdk::prelude::{
        Address, ArchiveFilter, DocumentView, QualifiedPath, QueryFilter,
    },
};
use tokio::time::Duration;
use typeshare::typeshare;

/// IPC request information.
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequest {
    /// Request identifier.
    #[serde(rename = "id")]
    pub message_id: u32,
    /// Request payload.
    pub payload: IpcRequestBody,
}

/// IPC request information.
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "body")]
pub enum IpcRequestBody {
    /// HTTP request routed to the local server.
    Http(LocalRequest),
}

impl IpcRequest {
    /// Duration allowed for a request.
    pub fn timeout_duration(&self) -> Duration {
        Duration::from_secs(15)
    }
}

impl From<IpcRequest> for WireIpcRequest {
    fn from(value: IpcRequest) -> Self {
        match value.payload {
            IpcRequestBody::Http(req) => WireIpcRequest {
                message_id: value.message_id,
                body: Some(WireIpcRequestBody {
                    inner: Some(wire_ipc_request_body::Inner::Http(
                        req.into(),
                    )),
                }),
            },
        }
    }
}

impl TryFrom<WireIpcRequest> for IpcRequest {
    type Error = Error;

    fn try_from(value: WireIpcRequest) -> Result<Self> {
        let message_id = value.message_id;
        let body = value.body.ok_or(Error::DecodeRequest)?;
        Ok(match body.inner {
            Some(wire_ipc_request_body::Inner::Http(body)) => IpcRequest {
                message_id,
                payload: IpcRequestBody::Http(body.try_into()?),
            },
            _ => return Err(Error::DecodeRequest),
        })
    }
}
