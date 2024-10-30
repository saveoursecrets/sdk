use sos_net::sdk::prelude::PublicIdentity;

use super::WirePublicIdentity;
use crate::{
    ipc_response_body, AccountsList, Error, IpcResponse, IpcResponseBody,
    Result, WireAccountInfo, WireAccountList,
};

impl IpcResponse {
    /// Create an accounts list response.
    pub fn new_accounts_list(message_id: u64, data: AccountsList) -> Self {
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
            body: Some(IpcResponseBody {
                inner: Some(ipc_response_body::Inner::Authenticated(list)),
            }),
        }
    }
}

/// Convert a response to an accounts list.
impl TryFrom<IpcResponse> for AccountsList {
    type Error = crate::Error;

    fn try_from(value: IpcResponse) -> Result<Self> {
        let body = value.body.ok_or(Error::DecodeResponse)?;
        match body.inner {
            Some(ipc_response_body::Inner::Authenticated(list)) => {
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
                Ok(data)
            }
            _ => Err(Error::DecodeResponse),
        }
    }
}
