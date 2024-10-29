use protocol::WireIpcResponse;

use super::*;

#[derive(Debug)]
pub struct IpcResponse {
    /// Message identifier.
    pub message_id: u64,
}

impl TryFrom<WireIpcResponse> for IpcResponse {
    type Error = crate::Error;

    fn try_from(value: WireIpcResponse) -> Result<Self, Self::Error> {
        todo!();
    }
}

impl From<IpcResponse> for WireIpcResponse {
    fn from(value: IpcResponse) -> Self {
        todo!();
    }
}
