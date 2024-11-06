include!(concat!(env!("OUT_DIR"), "/response.rs"));

use crate::{AccountsList, Error, Result, SearchResults};
use serde::{Deserialize, Serialize};
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
    /// Search query response.
    Search(SearchResults),
    /// Query view response.
    QueryView(SearchResults),
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
                                public_id: Some(public_id.into()),
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
                IpcResponseBody::Search(accounts) => Self {
                    message_id,
                    result: Some(wire_ipc_response::Result::Body(
                        WireIpcResponseBody {
                            inner: Some(
                                wire_ipc_response_body::Inner::Search(
                                    accounts.into(),
                                ),
                            ),
                        },
                    )),
                },
                IpcResponseBody::QueryView(accounts) => Self {
                    message_id,
                    result: Some(wire_ipc_response::Result::Body(
                        WireIpcResponseBody {
                            inner: Some(
                                wire_ipc_response_body::Inner::QueryView(
                                    accounts.into(),
                                ),
                            ),
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
                    Some(wire_ipc_response_body::Inner::Status(inner)) => {
                        IpcResponse::Value {
                            message_id,
                            payload: IpcResponseBody::Status {
                                app: inner.app,
                                ipc: inner.ipc,
                            },
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
                    Some(wire_ipc_response_body::Inner::ListAccounts(
                        inner,
                    )) => {
                        let mut data = Vec::new();
                        for item in inner.accounts {
                            let public_id = item.public_id.unwrap();
                            data.push((
                                public_id.try_into()?,
                                item.authenticated,
                            ));
                        }
                        IpcResponse::Value {
                            message_id,
                            payload: IpcResponseBody::Accounts(data),
                        }
                    }
                    Some(wire_ipc_response_body::Inner::Authenticate(
                        inner,
                    )) => {
                        let outcome: WireCommandOutcome = inner.try_into()?;
                        IpcResponse::Value {
                            message_id,
                            payload: IpcResponseBody::Authenticate(
                                outcome.try_into()?,
                            ),
                        }
                    }
                    Some(wire_ipc_response_body::Inner::Lock(inner)) => {
                        let outcome: WireCommandOutcome = inner.try_into()?;
                        IpcResponse::Value {
                            message_id,
                            payload: IpcResponseBody::Lock(
                                outcome.try_into()?,
                            ),
                        }
                    }
                    Some(wire_ipc_response_body::Inner::Search(inner)) => {
                        IpcResponse::Value {
                            message_id,
                            payload: IpcResponseBody::Search(
                                inner.try_into()?,
                            ),
                        }
                    }
                    Some(wire_ipc_response_body::Inner::QueryView(inner)) => {
                        IpcResponse::Value {
                            message_id,
                            payload: IpcResponseBody::QueryView(
                                inner.try_into()?,
                            ),
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
            _ => unreachable!("unknown command outcome variant"),
        })
    }
}

impl From<SearchResults> for WireSearchResults {
    fn from(value: SearchResults) -> Self {
        WireSearchResults {
            accounts: value
                .into_iter()
                .map(|(identity, documents)| WireAccountSearchResults {
                    identity: Some(identity.into()),
                    documents: documents
                        .into_iter()
                        .map(|d| d.into())
                        .collect(),
                })
                .collect(),
        }
    }
}

impl TryFrom<WireSearchResults> for SearchResults {
    type Error = Error;

    fn try_from(value: WireSearchResults) -> Result<Self> {
        let mut results = Vec::with_capacity(value.accounts.len());
        for account in value.accounts {
            let identity = account.identity.unwrap();
            let mut documents = Vec::with_capacity(account.documents.len());
            for doc in account.documents {
                documents.push(doc.try_into()?);
            }
            results.push((identity.try_into()?, documents));
        }
        Ok(results)
    }
}
