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
    /// Probe the native bridge for aliveness.
    ///
    /// Used to test whether the executable is running
    /// and the native messaging API is connected.
    Probe,
    /// Query app info.
    Info,
    /// Query app status.
    Status,
    /// Ping the server.
    Ping,
    /// Request to open a URL.
    OpenUrl(String),
    /// HTTP request routed to the local server.
    Http(LocalRequest),
    /*
    /// Request the accounts list.
    ListAccounts,
    /// Request to copy to the clipboard.
    Copy(ClipboardTarget),
    /// Request authentication for an account.
    Authenticate {
        /// Account address.
        address: Address,
    },
    /// Request to lock an account.
    Lock {
        /// Account address.
        address: Option<Address>,
    },
    /// Request to search the index.
    Search {
        /// Query needle.
        needle: String,
        /// Query filter.
        filter: QueryFilter,
    },
    /// Request to query views in the search index.
    QueryView {
        /// Document views.
        views: Vec<DocumentView>,
        /// Archive filter.
        archive_filter: Option<ArchiveFilter>,
    },
    */
    /*
    /// Request to read a secret.
    ReadSecret {
        /// Qualified path to the secret.
        path: QualifiedPath,
    },
    */
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
            IpcRequestBody::Probe => WireIpcRequest {
                message_id: value.message_id,
                body: Some(WireIpcRequestBody {
                    inner: Some(wire_ipc_request_body::Inner::Probe(
                        WireVoidBody {},
                    )),
                }),
            },
            IpcRequestBody::Info => WireIpcRequest {
                message_id: value.message_id,
                body: Some(WireIpcRequestBody {
                    inner: Some(wire_ipc_request_body::Inner::Info(
                        WireVoidBody {},
                    )),
                }),
            },
            IpcRequestBody::Status => WireIpcRequest {
                message_id: value.message_id,
                body: Some(WireIpcRequestBody {
                    inner: Some(wire_ipc_request_body::Inner::Status(
                        WireVoidBody {},
                    )),
                }),
            },
            IpcRequestBody::Ping => WireIpcRequest {
                message_id: value.message_id,
                body: Some(WireIpcRequestBody {
                    inner: Some(wire_ipc_request_body::Inner::Ping(
                        WireVoidBody {},
                    )),
                }),
            },
            IpcRequestBody::OpenUrl(url) => WireIpcRequest {
                message_id: value.message_id,
                body: Some(WireIpcRequestBody {
                    inner: Some(wire_ipc_request_body::Inner::OpenUrl(
                        WireOpenUrlBody { url },
                    )),
                }),
            },
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
            Some(wire_ipc_request_body::Inner::Probe(_)) => IpcRequest {
                message_id,
                payload: IpcRequestBody::Probe,
            },
            Some(wire_ipc_request_body::Inner::Info(_)) => IpcRequest {
                message_id,
                payload: IpcRequestBody::Info,
            },
            Some(wire_ipc_request_body::Inner::Status(_)) => IpcRequest {
                message_id,
                payload: IpcRequestBody::Status,
            },
            Some(wire_ipc_request_body::Inner::Ping(_)) => IpcRequest {
                message_id,
                payload: IpcRequestBody::Ping,
            },
            Some(wire_ipc_request_body::Inner::OpenUrl(body)) => IpcRequest {
                message_id,
                payload: IpcRequestBody::OpenUrl(body.url),
            },
            Some(wire_ipc_request_body::Inner::Http(body)) => IpcRequest {
                message_id,
                payload: IpcRequestBody::Http(body.try_into()?),
            },
            _ => return Err(Error::DecodeRequest),
        })
    }
}

/// Target for a clipboard copy operation.
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClipboardTarget {
    /// Qualified path to the secret.
    pub path: QualifiedPath,
}

impl From<ClipboardTarget> for WireClipboardTarget {
    fn from(value: ClipboardTarget) -> Self {
        WireClipboardTarget {
            path: Some(value.path.into()),
        }
    }
}

impl TryFrom<WireClipboardTarget> for ClipboardTarget {
    type Error = Error;

    fn try_from(value: WireClipboardTarget) -> Result<Self> {
        Ok(ClipboardTarget {
            path: value.path.unwrap().try_into()?,
        })
    }
}
