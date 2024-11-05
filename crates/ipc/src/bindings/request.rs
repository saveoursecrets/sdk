include!(concat!(env!("OUT_DIR"), "/request.rs"));

use crate::{Error, Result, WireVoidBody};
use serde::{Deserialize, Serialize};
use sos_net::sdk::prelude::Address;
use tokio::time::Duration;

/// IPC request information.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "body")]
pub enum IpcRequest {
    /// Query app status.
    Status,
    /// Ping the server.
    Ping,
    /// Request to open a URL.
    OpenUrl(String),
    /// Request the accounts list.
    ListAccounts,
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
}

impl IpcRequest {
    /// Duration allowed for a request.
    pub fn timeout_duration(&self) -> Duration {
        match self {
            #[cfg(debug_assertions)]
            IpcRequest::Authenticate { .. } => Duration::from_secs(5),
            #[cfg(not(debug_assertions))]
            IpcRequest::Authenticate { .. } => Duration::from_secs(60),
            _ => Duration::from_secs(5),
        }
    }
}

impl From<(u64, IpcRequest)> for WireIpcRequest {
    fn from(value: (u64, IpcRequest)) -> Self {
        let (message_id, req) = value;
        match req {
            IpcRequest::Status => WireIpcRequest {
                message_id,
                body: Some(WireIpcRequestBody {
                    inner: Some(wire_ipc_request_body::Inner::Status(
                        WireVoidBody {},
                    )),
                }),
            },
            IpcRequest::Ping => WireIpcRequest {
                message_id,
                body: Some(WireIpcRequestBody {
                    inner: Some(wire_ipc_request_body::Inner::Ping(
                        WireVoidBody {},
                    )),
                }),
            },
            IpcRequest::OpenUrl(url) => WireIpcRequest {
                message_id,
                body: Some(WireIpcRequestBody {
                    inner: Some(wire_ipc_request_body::Inner::OpenUrl(
                        WireOpenUrlBody { url },
                    )),
                }),
            },
            IpcRequest::ListAccounts => WireIpcRequest {
                message_id,
                body: Some(WireIpcRequestBody {
                    inner: Some(wire_ipc_request_body::Inner::ListAccounts(
                        WireVoidBody {},
                    )),
                }),
            },
            IpcRequest::Authenticate { address } => WireIpcRequest {
                message_id,
                body: Some(WireIpcRequestBody {
                    inner: Some(wire_ipc_request_body::Inner::Authenticate(
                        WireAuthenticateBody {
                            address: address.to_string(),
                        },
                    )),
                }),
            },
            IpcRequest::Lock { address } => WireIpcRequest {
                message_id,
                body: Some(WireIpcRequestBody {
                    inner: Some(wire_ipc_request_body::Inner::Lock(
                        WireLockBody {
                            address: address.map(|a| a.to_string()),
                        },
                    )),
                }),
            },
        }
    }
}

impl TryFrom<WireIpcRequest> for (u64, IpcRequest) {
    type Error = Error;

    fn try_from(value: WireIpcRequest) -> Result<Self> {
        let message_id = value.message_id;
        let body = value.body.ok_or(Error::DecodeRequest)?;
        Ok(match body.inner {
            Some(wire_ipc_request_body::Inner::Status(_)) => {
                (message_id, IpcRequest::Status)
            }
            Some(wire_ipc_request_body::Inner::Ping(_)) => {
                (message_id, IpcRequest::Ping)
            }
            Some(wire_ipc_request_body::Inner::OpenUrl(body)) => {
                (message_id, IpcRequest::OpenUrl(body.url))
            }
            Some(wire_ipc_request_body::Inner::ListAccounts(_)) => {
                (message_id, IpcRequest::ListAccounts)
            }
            Some(wire_ipc_request_body::Inner::Authenticate(body)) => {
                let address: Address = body.address.parse()?;
                (message_id, IpcRequest::Authenticate { address })
            }
            Some(wire_ipc_request_body::Inner::Lock(body)) => {
                let address = if let Some(address) = body.address {
                    let address: Address = address.parse()?;
                    Some(address)
                } else {
                    None
                };
                (message_id, IpcRequest::Lock { address })
            }
            _ => return Err(Error::DecodeRequest),
        })
    }
}
