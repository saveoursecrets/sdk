use super::{Error, Result};
use sos_sdk::{hex, url::Url};
use std::str::FromStr;

/// URL shared to offer device pairing via an untrusted relay server.
#[derive(Debug, Clone)]
pub struct ServerPairUrl {
    /// Server used to transfer the account data.
    server: Url,
    /// Public key of the noise protocol.
    public_key: Vec<u8>,
}

impl ServerPairUrl {
    /// Create a URL for pairing two devices.
    ///
    /// The public key is the noise protocol public key
    /// of the authenticated offering device.
    pub fn new(server: Url, public_key: Vec<u8>) -> Self {
        Self { server, public_key }
    }

    /// Server URL.
    pub fn server(&self) -> &Url {
        &self.server
    }

    /// Noise protocol public key.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

impl From<ServerPairUrl> for Url {
    fn from(value: ServerPairUrl) -> Self {
        let mut url = Url::parse("data:text/plain,sos-pair").unwrap();
        let key = hex::encode(&value.public_key);
        url.query_pairs_mut()
            .append_pair("url", &value.server.to_string())
            .append_pair("key", &key);
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
            if q.0.as_ref() == "url" {
                Some(q.1)
            } else {
                None
            }
        });

        let server = server.ok_or(Error::InvalidShareUrl)?;
        let server: Url = server.as_ref().parse()?;

        let key = pairs.find_map(|q| {
            if q.0.as_ref() == "key" {
                Some(q.1)
            } else {
                None
            }
        });
        let key = key.ok_or(Error::InvalidShareUrl)?;
        let key = hex::decode(key.as_ref())?;

        Ok(Self {
            server,
            public_key: key,
        })
    }
}

#[cfg(test)]
mod test {
    use super::ServerPairUrl;
    use crate::sdk::url::Url;
    use anyhow::Result;

    #[test]
    fn server_pair_url() -> Result<()> {
        let mock_url = Url::parse("http://192.168.1.8:5053/foo?bar=baz+qux")?;
        let mock_key = vec![1, 2, 3, 4];
        let share = ServerPairUrl::new(mock_url.clone(), mock_key.clone());
        let share_url: Url = share.into();
        let share_url = share_url.to_string();
        let parsed_share: ServerPairUrl = share_url.parse()?;
        assert_eq!(mock_url, parsed_share.server);
        assert_eq!(&mock_key, parsed_share.public_key());
        Ok(())
    }
}
