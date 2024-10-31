use crate::{
    wire_ipc_request_body, WireIpcRequest, WireIpcRequestBody, WireVoidBody,
};
use serde::{Deserialize, Serialize};

/// Request a list of accounts.
#[derive(Serialize, Deserialize)]
pub struct AccountsListRequest;

impl From<(u64, AccountsListRequest)> for WireIpcRequest {
    fn from(value: (u64, AccountsListRequest)) -> Self {
        let (message_id, _) = value;
        WireIpcRequest {
            message_id,
            body: Some(WireIpcRequestBody {
                inner: Some(wire_ipc_request_body::Inner::ListAccounts(
                    WireVoidBody {},
                )),
            }),
        }
    }
}
