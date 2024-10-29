use crate::{IpcRequest, IpcResponse, Result};

pub struct IpcService {}

impl IpcService {
    pub fn new() -> Self {
        Self {}
    }

    /// Handle an incoming request.
    pub async fn handle(
        &mut self,
        request: IpcRequest,
    ) -> Result<IpcResponse> {
        let response = IpcResponse {
            message_id: request.message_id,
        };
        Ok(response)
    }
}
