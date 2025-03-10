use super::{Error, Result};
use hex;
use rand::Rng;
use sos_core::{csprng, AccountId};
use std::str::FromStr;
use url::Url;

/// Account identifier.
const AID: &str = "aid";
/// Server URL.
const URL: &str = "url";
/// Noise public key.
const KEY: &str = "key";
/// Symmetric pre-shared key.
const PSK: &str = "psk";

/// URL shared to offer device pairing via an untrusted relay server.
#[derive(Debug, Clone)]
pub struct ServerPairUrl {
    /// Account identifier.
    account_id: AccountId,
    /// Server used to transfer the account data.
    server: Url,
    /// Public key of the noise protocol.
    public_key: Vec<u8>,
    /// Symmetric pre-shared key.
    pre_shared_key: [u8; 32],
}

impl ServerPairUrl {
    /// Create a URL for pairing two devices.
    ///
    /// The public key is the noise protocol public key
    /// of the device.
    pub fn new(
        account_id: AccountId,
        server: Url,
        public_key: Vec<u8>,
    ) -> Self {
        let pre_shared_key: [u8; 32] = csprng().gen();
        Self {
            account_id,
            server,
            public_key,
            pre_shared_key,
        }
    }

    /// Account identifier.
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Server URL.
    pub fn server(&self) -> &Url {
        &self.server
    }

    /// Noise protocol public key.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Synmmetric pre-shared key.
    pub fn pre_shared_key(&self) -> [u8; 32] {
        self.pre_shared_key
    }
}

impl From<ServerPairUrl> for Url {
    fn from(value: ServerPairUrl) -> Self {
        let mut url = Url::parse("data:text/plain,sos-pair").unwrap();
        let key = hex::encode(&value.public_key);
        let psk = hex::encode(&value.pre_shared_key);
        url.query_pairs_mut()
            .append_pair(AID, &value.account_id.to_string())
            .append_pair(URL, &value.server.to_string())
            .append_pair(KEY, &key)
            .append_pair(PSK, &psk);
        url
    }
}

impl FromStr for ServerPairUrl {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let url = Url::parse(s)?;

        if url.scheme() != "data" {
            return Err(Error::InvalidShareUrl);
        }

        if url.path() != "text/plain,sos-pair" {
            return Err(Error::InvalidShareUrl);
        }

        let mut pairs = url.query_pairs();

        let account_id = pairs.find_map(|q| {
            if q.0.as_ref() == AID {
                Some(q.1)
            } else {
                None
            }
        });
        let account_id = account_id.ok_or(Error::InvalidShareUrl)?;
        let account_id: AccountId = account_id.as_ref().parse()?;

        let server = pairs.find_map(|q| {
            if q.0.as_ref() == URL {
                Some(q.1)
            } else {
                None
            }
        });
        let server = server.ok_or(Error::InvalidShareUrl)?;
        let server: Url = server.as_ref().parse()?;

        let key = pairs.find_map(|q| {
            if q.0.as_ref() == KEY {
                Some(q.1)
            } else {
                None
            }
        });
        let key = key.ok_or(Error::InvalidShareUrl)?;
        let key = hex::decode(key.as_ref())?;

        let psk = pairs.find_map(|q| {
            if q.0.as_ref() == PSK {
                Some(q.1)
            } else {
                None
            }
        });
        let psk = psk.ok_or(Error::InvalidShareUrl)?;
        let psk = hex::decode(psk.as_ref())?;
        let psk: [u8; 32] = psk.as_slice().try_into()?;

        Ok(Self {
            account_id,
            server,
            public_key: key,
            pre_shared_key: psk,
        })
    }
}
