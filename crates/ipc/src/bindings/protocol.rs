use crate::{Error, Result};
use sos_net::sdk::prelude::Address;
use std::collections::HashMap;

include!(concat!(env!("OUT_DIR"), "/protocol.rs"));

impl IpcResponse {
    /// Create an authenticated response.
    pub fn new_authenticated(
        message_id: u64,
        data: HashMap<Address, bool>,
    ) -> Self {
        let list = AccountList {
            accounts: data
                .into_iter()
                .map(|(key, val)| AccountAuthenticatedState {
                    address: key.to_string(),
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

    /// Convert to authenticated data.
    pub fn as_authenticated(self) -> Result<HashMap<Address, bool>> {
        let body = self.body.ok_or(Error::DecodeResponse)?;
        match body.inner {
            Some(ipc_response_body::Inner::Authenticated(list)) => {
                let mut data = HashMap::new();
                for item in list.accounts {
                    data.insert(item.address.parse()?, item.authenticated);
                }
                Ok(data)
            }
            _ => Err(Error::DecodeResponse),
        }
    }
}
