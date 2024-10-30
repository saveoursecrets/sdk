use crate::{ipc_request_body, IpcRequest, IpcRequestBody, VoidBody};
use serde::{Deserialize, Serialize};

/// Request a list of accounts.
#[derive(Serialize, Deserialize)]
pub struct AccountsListRequest;

impl From<(u64, AccountsListRequest)> for IpcRequest {
    fn from(value: (u64, AccountsListRequest)) -> Self {
        let (message_id, _) = value;
        IpcRequest {
            message_id,
            body: Some(IpcRequestBody {
                inner: Some(ipc_request_body::Inner::Authenticated(
                    VoidBody {},
                )),
            }),
        }
    }
}
