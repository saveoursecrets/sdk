use serde::{Deserialize, Serialize};
use sos_net::sdk::prelude::PublicIdentity;

use crate::{
    wire_ipc_response, wire_ipc_response_body, AccountsList, Error, Result,
    WireAccountInfo, WireAccountList, WireCommandOutcome, WireIpcResponse,
    WireIpcResponseBody, WireIpcResponseError, WireOpenUrl,
    WirePublicIdentity, WireStatusBody,
};

use super::WireVoidBody;

/// IPC response information.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum IpcResponse {
    /// Error response.
    Error(IpcResponseError),
    /// Response body.
    Body(IpcResponseBody),
}

/// IPC response body.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "body")]
pub enum IpcResponseBody {
    /// Status information.
    Status {
        /// Whether the app is running as determined
        /// by an active account file lock.
        app: bool,
        /// Whether the IPC channel is responding to a ping.
        ipc: bool,
    },
    /// Reply to a ping.
    Pong,
    /// Result of opening a URL.
    OpenUrl(bool),
    /// List of accounts.
    Accounts(AccountsList),
    /// Authenticate response.
    Authenticate(CommandOutcome),
    /// Lock response.
    Lock(CommandOutcome),
}

/// IPC response error.
#[derive(Debug, Serialize, Deserialize)]
pub struct IpcResponseError {
    /// Error code.
    pub code: i32,
    /// Error message.
    pub message: String,
}

/// Generic command outcome.
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
            _ => unreachable!(),
        })
    }
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
        }
    }
}

impl From<(u64, IpcResponse)> for WireIpcResponse {
    fn from(value: (u64, IpcResponse)) -> Self {
        let (message_id, res) = value;

        match res {
            IpcResponse::Body(body) => match body {
                IpcResponseBody::Status { app, ipc } => Self {
                    message_id,
                    result: Some(wire_ipc_response::Result::Body(
                        WireIpcResponseBody {
                            inner: Some(
                                wire_ipc_response_body::Inner::Status(
                                    WireStatusBody { app, ipc },
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

                IpcResponseBody::Accounts(data) => {
                    let list = WireAccountList {
                        accounts: data
                            .into_iter()
                            .map(|(public_id, val)| WireAccountInfo {
                                public_id: Some(WirePublicIdentity {
                                    address: public_id.address().to_string(),
                                    label: public_id.label().to_string(),
                                }),
                                authenticated: val,
                            })
                            .collect(),
                    };

                    Self {
                        message_id,
                        result: Some(wire_ipc_response::Result::Body(

                        WireIpcResponseBody {
                            inner: Some(
                                wire_ipc_response_body::Inner::ListAccounts(
                                    list,
                                ),
                            ),
                        },
                        )),
                    }
                }
                IpcResponseBody::Authenticate(outcome) => Self {
                    message_id,
                    result: Some(wire_ipc_response::Result::Body(
                        WireIpcResponseBody {
                            inner: Some(
                                wire_ipc_response_body::Inner::Authenticate(
                                    WireCommandOutcome::from(outcome) as i32,
                                ),
                            ),
                        },
                    )),
                },
                IpcResponseBody::Lock(outcome) => Self {
                    message_id,
                    result: Some(wire_ipc_response::Result::Body(
                        WireIpcResponseBody {
                            inner: Some(wire_ipc_response_body::Inner::Lock(
                                WireCommandOutcome::from(outcome) as i32,
                            )),
                        },
                    )),
                },
            },
            IpcResponse::Error(err) => Self {
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

impl TryFrom<WireIpcResponse> for (u64, IpcResponse) {
    type Error = Error;

    fn try_from(value: WireIpcResponse) -> Result<Self> {
        let message_id = value.message_id;

        match value.result {
            Some(wire_ipc_response::Result::Body(body)) => {
                Ok(match body.inner {
                    Some(wire_ipc_response_body::Inner::Status(inner)) => (
                        message_id,
                        IpcResponse::Body(IpcResponseBody::Status {
                            app: inner.app,
                            ipc: inner.ipc,
                        }),
                    ),
                    Some(wire_ipc_response_body::Inner::Pong(_)) => {
                        (message_id, IpcResponse::Body(IpcResponseBody::Pong))
                    }
                    Some(wire_ipc_response_body::Inner::OpenUrl(inner)) => (
                        message_id,
                        IpcResponse::Body(IpcResponseBody::OpenUrl(
                            inner.is_ok,
                        )),
                    ),
                    Some(wire_ipc_response_body::Inner::ListAccounts(
                        inner,
                    )) => {
                        let mut data = Vec::new();
                        for item in inner.accounts {
                            let public_id = item.public_id.unwrap();
                            data.push((
                                PublicIdentity::new(
                                    public_id.label,
                                    public_id.address.parse()?,
                                ),
                                item.authenticated,
                            ));
                        }
                        (
                            message_id,
                            IpcResponse::Body(IpcResponseBody::Accounts(
                                data,
                            )),
                        )
                    }
                    Some(wire_ipc_response_body::Inner::Authenticate(
                        inner,
                    )) => {
                        let outcome: WireCommandOutcome = inner.try_into()?;
                        (
                            message_id,
                            IpcResponse::Body(IpcResponseBody::Authenticate(
                                outcome.try_into()?,
                            )),
                        )
                    }
                    Some(wire_ipc_response_body::Inner::Lock(inner)) => {
                        let outcome: WireCommandOutcome = inner.try_into()?;
                        (
                            message_id,
                            IpcResponse::Body(IpcResponseBody::Lock(
                                outcome.try_into()?,
                            )),
                        )
                    }
                    _ => return Err(Error::DecodeResponse),
                })
            }
            Some(wire_ipc_response::Result::Error(error)) => Ok((
                message_id,
                IpcResponse::Error(IpcResponseError {
                    code: error.code,
                    message: error.message,
                }),
            )),
            _ => return Err(Error::DecodeResponse),
        }
    }
}
