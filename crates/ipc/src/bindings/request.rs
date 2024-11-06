include!(concat!(env!("OUT_DIR"), "/request.rs"));

use crate::{Error, Result, WireVoidBody};
use serde::{Deserialize, Serialize};
use sos_net::sdk::prelude::{
    Address, ArchiveFilter, DocumentView, QueryFilter,
};
use tokio::time::Duration;

/// IPC request information.
#[derive(Debug, Serialize, Deserialize)]
pub struct IpcRequest {
    /// Request identifier.
    #[serde(rename = "id")]
    pub message_id: u64,
    /// Request payload.
    pub payload: IpcRequestBody,
}

/// IPC request information.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "body")]
pub enum IpcRequestBody {
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
}

impl IpcRequest {
    /// Duration allowed for a request.
    pub fn timeout_duration(&self) -> Duration {
        match &self.payload {
            #[cfg(debug_assertions)]
            IpcRequestBody::Authenticate { .. } => Duration::from_secs(15),
            #[cfg(not(debug_assertions))]
            IpcRequestBody::Authenticate { .. } => Duration::from_secs(60),
            _ => Duration::from_secs(15),
        }
    }
}

impl From<IpcRequest> for WireIpcRequest {
    fn from(value: IpcRequest) -> Self {
        match value.payload {
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
            IpcRequestBody::ListAccounts => WireIpcRequest {
                message_id: value.message_id,
                body: Some(WireIpcRequestBody {
                    inner: Some(wire_ipc_request_body::Inner::ListAccounts(
                        WireVoidBody {},
                    )),
                }),
            },
            IpcRequestBody::Authenticate { address } => WireIpcRequest {
                message_id: value.message_id,
                body: Some(WireIpcRequestBody {
                    inner: Some(wire_ipc_request_body::Inner::Authenticate(
                        WireAuthenticateBody {
                            address: address.to_string(),
                        },
                    )),
                }),
            },
            IpcRequestBody::Lock { address } => WireIpcRequest {
                message_id: value.message_id,
                body: Some(WireIpcRequestBody {
                    inner: Some(wire_ipc_request_body::Inner::Lock(
                        WireLockBody {
                            address: address.map(|a| a.to_string()),
                        },
                    )),
                }),
            },
            IpcRequestBody::Search { needle, filter } => WireIpcRequest {
                message_id: value.message_id,
                body: Some(WireIpcRequestBody {
                    inner: Some(wire_ipc_request_body::Inner::Search(
                        WireSearchBody {
                            needle,
                            filter: Some(filter.into()),
                        },
                    )),
                }),
            },
            IpcRequestBody::QueryView {
                views,
                archive_filter,
            } => WireIpcRequest {
                message_id: value.message_id,
                body: Some(WireIpcRequestBody {
                    inner: Some(wire_ipc_request_body::Inner::QueryView(
                        WireQueryViewBody {
                            views: views
                                .into_iter()
                                .map(|v| v.into())
                                .collect(),
                            archive_filter: archive_filter.map(|f| f.into()),
                        },
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
            Some(wire_ipc_request_body::Inner::ListAccounts(_)) => {
                IpcRequest {
                    message_id,
                    payload: IpcRequestBody::ListAccounts,
                }
            }
            Some(wire_ipc_request_body::Inner::Authenticate(body)) => {
                let address: Address = body.address.parse()?;
                IpcRequest {
                    message_id,
                    payload: IpcRequestBody::Authenticate { address },
                }
            }
            Some(wire_ipc_request_body::Inner::Lock(body)) => {
                let address = if let Some(address) = body.address {
                    let address: Address = address.parse()?;
                    Some(address)
                } else {
                    None
                };
                IpcRequest {
                    message_id,
                    payload: IpcRequestBody::Lock { address },
                }
            }
            Some(wire_ipc_request_body::Inner::Search(body)) => IpcRequest {
                message_id,
                payload: IpcRequestBody::Search {
                    needle: body.needle,
                    filter: body.filter.unwrap().try_into()?,
                },
            },
            Some(wire_ipc_request_body::Inner::QueryView(body)) => {
                let mut views = Vec::with_capacity(body.views.len());
                for view in body.views {
                    views.push(view.try_into()?);
                }
                let archive_filter =
                    if let Some(archive_filter) = body.archive_filter {
                        Some(archive_filter.try_into()?)
                    } else {
                        None
                    };
                IpcRequest {
                    message_id,
                    payload: IpcRequestBody::QueryView {
                        views,
                        archive_filter,
                    },
                }
            }
            _ => return Err(Error::DecodeRequest),
        })
    }
}
