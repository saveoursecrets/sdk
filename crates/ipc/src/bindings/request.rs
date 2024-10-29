use super::protocol::*;

#[derive(Debug)]
pub struct IpcRequest {
    /// Message identifier.
    pub message_id: u64,
}

impl TryFrom<WireIpcRequest> for IpcRequest {
    type Error = crate::Error;

    fn try_from(value: WireIpcRequest) -> Result<Self, Self::Error> {
        todo!();
    }
}

impl From<IpcRequest> for WireIpcRequest {
    fn from(value: IpcRequest) -> Self {
        todo!();
    }
}
