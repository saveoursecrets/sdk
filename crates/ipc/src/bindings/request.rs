use crate::{
    wire_ipc_request_body, WireIpcRequest, WireIpcRequestBody, WireVoidBody,
};
use serde::{Deserialize, Serialize};
use sos_net::sdk::prelude::Address;

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
