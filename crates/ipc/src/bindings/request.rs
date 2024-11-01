use crate::{
    wire_ipc_request_body, Error, Result, WireIpcRequest, WireIpcRequestBody,
    WireVoidBody,
};
use serde::{Deserialize, Serialize};
use sos_net::sdk::prelude::Address;
use tokio::time::Duration;

use super::WireAuthenticateBody;

/// IPC request information.
#[derive(Debug, Serialize, Deserialize)]
pub enum IpcRequest {
    /// Request the accounts list.
    ListAccounts,
    /// Request authentication for an account.
    Authenticate {
        /// Account address.
        address: Address,
    },
}

impl IpcRequest {
    /// Duration allowed for a request.
    pub fn timeout_duration(&self) -> Duration {
        match self {
            IpcRequest::Authenticate { .. } => Duration::from_secs(60),
            _ => Duration::from_secs(5),
        }
    }
}

impl From<(u64, IpcRequest)> for WireIpcRequest {
    fn from(value: (u64, IpcRequest)) -> Self {
        let (message_id, req) = value;
        match req {
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
        }
    }
}

impl TryFrom<WireIpcRequest> for (u64, IpcRequest) {
    type Error = Error;

    fn try_from(value: WireIpcRequest) -> Result<Self> {
        let message_id = value.message_id;
        let body = value.body.ok_or(Error::DecodeRequest)?;
        Ok(match body.inner {
            Some(wire_ipc_request_body::Inner::ListAccounts(_)) => {
                (message_id, IpcRequest::ListAccounts)
            }
            Some(wire_ipc_request_body::Inner::Authenticate(body)) => {
                let address: Address = body.address.parse()?;
                (message_id, IpcRequest::Authenticate { address })
            }
            _ => return Err(Error::DecodeRequest),
        })
    }
}
