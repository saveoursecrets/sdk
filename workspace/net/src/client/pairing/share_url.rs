use super::{Error, Result};
use sos_sdk::{hex, url::Url};
use std::str::FromStr;

/// Server URL.
const URL: &str = "url";
/// Noise public key.
const KEY: &str = "key";
/// Symmetric pre-shared key.
const PSK: &str = "psk";

/// URL shared to offer device pairing via an untrusted relay server.
#[derive(Debug, Clone)]
pub struct ServerPairUrl {
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
    /// of the authenticated offering device.
    pub fn new(
        server: Url,
        public_key: Vec<u8>,
        pre_shared_key: [u8; 32],
    ) -> Self {
        Self {
            server,
            public_key,
            pre_shared_key,
        }
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
            server,
            public_key: key,
            pre_shared_key: psk,
        })
    }
}

#[cfg(test)]
mod test {
    use super::ServerPairUrl;
    use crate::sdk::{crypto::csprng, url::Url};
    use anyhow::Result;
    use rand::Rng;

    #[test]
    fn server_pair_url() -> Result<()> {
        let mock_psk: [u8; 32] = csprng().gen();
        let mock_url = Url::parse("http://192.168.1.8:5053/foo?bar=baz+qux")?;
        let mock_key = vec![1, 2, 3, 4];
        let share =
            ServerPairUrl::new(mock_url.clone(), mock_key.clone(), mock_psk);
        let share_url: Url = share.into();
        let share_url = share_url.to_string();
        let parsed_share: ServerPairUrl = share_url.parse()?;
        assert_eq!(mock_url, parsed_share.server);
        assert_eq!(&mock_key, parsed_share.public_key());
        assert_eq!(mock_psk, parsed_share.pre_shared_key());
        Ok(())
    }
}
