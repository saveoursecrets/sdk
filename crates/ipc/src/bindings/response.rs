use serde::{Deserialize, Serialize};
use sos_net::sdk::prelude::PublicIdentity;

use super::{
    wire_ipc_response, WireAuthenticateOutcome, WireIpcResponseError,
    WirePublicIdentity,
};
use crate::{
    wire_ipc_response_body, AccountsList, Error, Result, WireAccountInfo,
    WireAccountList, WireIpcResponse, WireIpcResponseBody,
};

/// IPC response information.
#[derive(Debug, Serialize, Deserialize)]
pub enum IpcResponse {
    /// Error response.
    Error(IpcResponseError),
    /// Response body.
    Body(IpcResponseBody),
}

/// IPC response body.
#[derive(Debug, Serialize, Deserialize)]
pub enum IpcResponseBody {
    /// List of accounts.
    ListAccounts(AccountsList),
    /// Authenticate response.
    Authenticate(AuthenticateOutcome),
}

/// IPC response error.
#[derive(Debug, Serialize, Deserialize)]
pub struct IpcResponseError {
    /// Error code.
    pub code: i32,
    /// Error message.
    pub message: String,
}

/// Outcome of an authentication request.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthenticateOutcome {
    /// Account not found.
    NotFound,
    /// Account was authenticated.
    Success,
    /// User canceled.
    Canceled,
    /// Timed out waiting for user input.
    TimedOut,
}

impl TryFrom<WireAuthenticateOutcome> for AuthenticateOutcome {
    type Error = Error;

    fn try_from(value: WireAuthenticateOutcome) -> Result<Self> {
        let name = value.as_str_name();
        Ok(match name {
            "NotFound" => AuthenticateOutcome::NotFound,
            "Success" => AuthenticateOutcome::Success,
            "Canceled" => AuthenticateOutcome::Canceled,
            "TimedOut" => AuthenticateOutcome::TimedOut,
            _ => unreachable!(),
        })
    }
}

impl From<AuthenticateOutcome> for WireAuthenticateOutcome {
    fn from(value: AuthenticateOutcome) -> Self {
        match value {
            AuthenticateOutcome::NotFound => {
                WireAuthenticateOutcome::from_str_name("NotFound").unwrap()
            }
            AuthenticateOutcome::Success => {
                WireAuthenticateOutcome::from_str_name("Success").unwrap()
            }
            AuthenticateOutcome::Canceled => {
                WireAuthenticateOutcome::from_str_name("Canceled").unwrap()
            }
            AuthenticateOutcome::TimedOut => {
                WireAuthenticateOutcome::from_str_name("TimedOut").unwrap()
            }
        }
    }
}

impl From<(u64, IpcResponse)> for WireIpcResponse {
    fn from(value: (u64, IpcResponse)) -> Self {
        let (message_id, res) = value;

        match res {
            IpcResponse::Body(body) => match body {
                IpcResponseBody::ListAccounts(data) => {
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
                                    WireAuthenticateOutcome::from(outcome)
                                        as i32,
                                ),
                            ),
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
                    Some(wire_ipc_response_body::Inner::ListAccounts(
                        list,
                    )) => {
                        let mut data = Vec::new();
                        for item in list.accounts {
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
                            IpcResponse::Body(IpcResponseBody::ListAccounts(
                                data,
                            )),
                        )
                    }
                    Some(wire_ipc_response_body::Inner::Authenticate(
                        outcome,
                    )) => {
                        let outcome: WireAuthenticateOutcome =
                            outcome.try_into()?;
                        (
                            message_id,
                            IpcResponse::Body(IpcResponseBody::Authenticate(
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
