include!(concat!(env!("OUT_DIR"), "/response.rs"));

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sos_net::{
    protocol::local_transport::LocalResponse,
    sdk::{
        vault::{Summary, VaultId},
        Error as SdkError,
    },
};
use typeshare::typeshare;

use super::WireVoidBody;

/// IPC response information.
#[typeshare]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "body")]
pub enum IpcResponse {
    /// Error response.
    #[serde(rename = "err")]
    Error {
        /// Message identifier.
        #[serde(rename = "id")]
        message_id: u32,
        /// Message payload.
        payload: IpcResponseError,
    },
    /// Response value.
    #[serde(rename = "ok")]
    Value {
        /// Message identifier.
        #[serde(rename = "id")]
        message_id: u32,
        /// Message payload.
        payload: IpcResponseBody,
    },
}

impl IpcResponse {
    /// Message identifier.
    pub fn message_id(&self) -> u32 {
        match self {
            Self::Error { message_id, .. } => *message_id,
            Self::Value { message_id, .. } => *message_id,
        }
    }
}

/// IPC response body.
#[typeshare]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "body")]
pub enum IpcResponseBody {
    /// Response to a probe request.
    Probe,
    /// App info.
    Info(ServiceAppInfo),
    /// App status.
    ///
    /// Whether the app is running as determined
    /// by an active app file lock.
    Status(bool),
    /// Reply to a ping.
    Pong,
    /// Result of opening a URL.
    OpenUrl(bool),
    /// Result invoking the local server.
    Http(LocalResponse),
    /*
    /// List of accounts.
    Accounts(AccountsList),
    /// Copy to clipboard result.
    Copy(CommandOutcome),
    /// Authenticate response.
    Authenticate(CommandOutcome),
    /// Lock response.
    Lock(CommandOutcome),
    /// Search query response.
    Search(SearchResults),
    /// Query view response.
    QueryView(SearchResults),
    */
}

/// IPC response error.
#[typeshare]
#[derive(Debug, Serialize, Deserialize)]
pub struct IpcResponseError {
    /// Error code.
    pub code: i32,
    /// Error message.
    pub message: String,
}

impl From<IpcResponse> for WireIpcResponse {
    fn from(value: IpcResponse) -> Self {
        match value {
            IpcResponse::Value {
                message_id,
                payload: body,
            } => match body {
                IpcResponseBody::Probe => Self {
                    message_id,
                    result: Some(wire_ipc_response::Result::Body(
                        WireIpcResponseBody {
                            inner: Some(
                                wire_ipc_response_body::Inner::Probe(
                                    WireVoidBody {},
                                ),
                            ),
                        },
                    )),
                },
                IpcResponseBody::Info(app) => Self {
                    message_id,
                    result: Some(wire_ipc_response::Result::Body(
                        WireIpcResponseBody {
                            inner: Some(wire_ipc_response_body::Inner::Info(
                                WireInfoBody {
                                    name: app.name,
                                    version: app.version,
                                    build_number: app.build_number,
                                },
                            )),
                        },
                    )),
                },
                IpcResponseBody::Status(app) => Self {
                    message_id,
                    result: Some(wire_ipc_response::Result::Body(
                        WireIpcResponseBody {
                            inner: Some(
                                wire_ipc_response_body::Inner::Status(
                                    WireStatusBody { app },
                                ),
                            ),
                        },
                    )),
                },

                IpcResponseBody::Pong => Self {
                    message_id,
                    result: Some(wire_ipc_response::Result::Body(
                        WireIpcResponseBody {
                            inner: Some(wire_ipc_response_body::Inner::Pong(
                                WireVoidBody {},
                            )),
                        },
                    )),
                },
                IpcResponseBody::OpenUrl(result) => Self {
                    message_id,
                    result: Some(wire_ipc_response::Result::Body(
                        WireIpcResponseBody {
                            inner: Some(
                                wire_ipc_response_body::Inner::OpenUrl(
                                    WireOpenUrl { is_ok: result },
                                ),
                            ),
                        },
                    )),
                },
                IpcResponseBody::Http(res) => Self {
                    message_id,
                    result: Some(wire_ipc_response::Result::Body(
                        WireIpcResponseBody {
                            inner: Some(wire_ipc_response_body::Inner::Http(
                                res.into(),
                            )),
                        },
                    )),
                },
            },
            IpcResponse::Error {
                message_id,
                payload: err,
            } => Self {
                message_id,
                result: Some(wire_ipc_response::Result::Error(
                    WireIpcResponseError {
                        code: err.code,
                        message: err.message,
                    },
                )),
            },
        }
    }
}

impl TryFrom<WireIpcResponse> for IpcResponse {
    type Error = Error;

    fn try_from(value: WireIpcResponse) -> Result<Self> {
        let message_id = value.message_id;
        match value.result {
            Some(wire_ipc_response::Result::Body(body)) => {
                Ok(match body.inner {
                    Some(wire_ipc_response_body::Inner::Probe(_)) => {
                        IpcResponse::Value {
                            message_id,
                            payload: IpcResponseBody::Probe,
                        }
                    }
                    Some(wire_ipc_response_body::Inner::Info(inner)) => {
                        IpcResponse::Value {
                            message_id,
                            payload: IpcResponseBody::Info(ServiceAppInfo {
                                name: inner.name,
                                version: inner.version,
                                build_number: inner.build_number,
                            }),
                        }
                    }
                    Some(wire_ipc_response_body::Inner::Status(inner)) => {
                        IpcResponse::Value {
                            message_id,
                            payload: IpcResponseBody::Status(inner.app),
                        }
                    }
                    Some(wire_ipc_response_body::Inner::Pong(_)) => {
                        IpcResponse::Value {
                            message_id,
                            payload: IpcResponseBody::Pong,
                        }
                    }
                    Some(wire_ipc_response_body::Inner::OpenUrl(inner)) => {
                        IpcResponse::Value {
                            message_id,
                            payload: IpcResponseBody::OpenUrl(inner.is_ok),
                        }
                    }
                    Some(wire_ipc_response_body::Inner::Http(res)) => {
                        IpcResponse::Value {
                            message_id,
                            payload: IpcResponseBody::Http(res.try_into()?),
                        }
                    }
                    _ => return Err(Error::DecodeResponse),
                })
            }
            Some(wire_ipc_response::Result::Error(error)) => {
                Ok(IpcResponse::Error {
                    message_id,
                    payload: IpcResponseError {
                        code: error.code,
                        message: error.message,
                    },
                })
            }
            _ => return Err(Error::DecodeResponse),
        }
    }
}

/// Generic command outcome.
#[typeshare]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CommandOutcome {
    /// Account not found.
    NotFound,
    /// Already authenticated.
    AlreadyAuthenticated,
    /// Not authenticated.
    NotAuthenticated,
    /// Account was authenticated.
    Success,
    /// Authentication failed.
    Failed,
    /// User canceled.
    Canceled,
    /// Timed out waiting for user input.
    TimedOut,
    /// Too many attempts to authenticate.
    Exhausted,
    /// Error attempting to get user input.
    InputError,
    /// Operation is not supported.
    Unsupported,
}

impl From<CommandOutcome> for WireCommandOutcome {
    fn from(value: CommandOutcome) -> Self {
        match value {
            CommandOutcome::NotFound => {
                WireCommandOutcome::from_str_name("NotFound").unwrap()
            }
            CommandOutcome::AlreadyAuthenticated => {
                WireCommandOutcome::from_str_name("AlreadyAuthenticated")
                    .unwrap()
            }
            CommandOutcome::NotAuthenticated => {
                WireCommandOutcome::from_str_name("NotAuthenticated").unwrap()
            }
            CommandOutcome::Success => {
                WireCommandOutcome::from_str_name("Success").unwrap()
            }
            CommandOutcome::Failed => {
                WireCommandOutcome::from_str_name("Failed").unwrap()
            }
            CommandOutcome::Canceled => {
                WireCommandOutcome::from_str_name("Canceled").unwrap()
            }
            CommandOutcome::TimedOut => {
                WireCommandOutcome::from_str_name("TimedOut").unwrap()
            }
            CommandOutcome::Exhausted => {
                WireCommandOutcome::from_str_name("Exhausted").unwrap()
            }
            CommandOutcome::InputError => {
                WireCommandOutcome::from_str_name("InputError").unwrap()
            }
            CommandOutcome::Unsupported => {
                WireCommandOutcome::from_str_name("Unsupported").unwrap()
            }
        }
    }
}

impl TryFrom<WireCommandOutcome> for CommandOutcome {
    type Error = Error;

    fn try_from(value: WireCommandOutcome) -> Result<Self> {
        let name = value.as_str_name();
        Ok(match name {
            "NotFound" => CommandOutcome::NotFound,
            "AlreadyAuthenticated" => CommandOutcome::AlreadyAuthenticated,
            "NotAuthenticated" => CommandOutcome::NotAuthenticated,
            "Success" => CommandOutcome::Success,
            "Failed" => CommandOutcome::Failed,
            "Canceled" => CommandOutcome::Canceled,
            "TimedOut" => CommandOutcome::TimedOut,
            "Exhausted" => CommandOutcome::Exhausted,
            "InputError" => CommandOutcome::InputError,
            "Unsupported" => CommandOutcome::Unsupported,
            _ => unreachable!("unknown command outcome variant"),
        })
    }
}

/// Information about the service.
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAppInfo {
    /// App name.
    pub name: String,
    /// App version.
    pub version: String,
    /// App build number.
    pub build_number: u32,
}

impl Default for ServiceAppInfo {
    fn default() -> Self {
        Self {
            name: env!("CARGO_PKG_NAME").to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            build_number: 0,
        }
    }
}

/// Information about a folder.
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderInfo {
    /// Name of the folder.
    pub name: String,
    /// Folder identifier.
    pub folder_id: VaultId,
}

impl From<&Summary> for FolderInfo {
    fn from(value: &Summary) -> Self {
        Self {
            name: value.name().to_string(),
            folder_id: *value.id(),
        }
    }
}

impl From<FolderInfo> for WireFolderInfo {
    fn from(value: FolderInfo) -> Self {
        WireFolderInfo {
            name: value.name,
            folder_id: value.folder_id.to_string(),
        }
    }
}

impl TryFrom<WireFolderInfo> for FolderInfo {
    type Error = Error;

    fn try_from(value: WireFolderInfo) -> Result<Self> {
        Ok(Self {
            name: value.name,
            folder_id: value.folder_id.parse().map_err(SdkError::from)?,
        })
    }
}
