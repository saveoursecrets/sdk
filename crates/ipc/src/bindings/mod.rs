mod common;
mod request;
mod response;
pub use request::{ClipboardTarget, IpcRequest, IpcRequestBody};
pub use response::{
    CommandOutcome, FolderInfo, IpcResponse, IpcResponseBody,
    IpcResponseError, ServiceAppInfo,
};

pub(crate) use common::*;
pub(crate) use request::WireIpcRequest;
pub(crate) use response::WireIpcResponse;
