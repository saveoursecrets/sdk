//! HTTP client helper functions.

use reqwest::Response;

use url::Url;

use crate::client::Result;

/// HTTP client implementation using the `reqwest` library.
#[derive(Clone)]
pub struct RequestClient;

impl RequestClient {
    /// Generic GET function.
    pub async fn get(url: Url) -> Result<Response> {
        let client = reqwest::Client::new();
        Ok(client.get(url).send().await?)
    }

    /// Get the server information.
    pub async fn server_info(server: Url) -> Result<Response> {
        let client = reqwest::Client::new();
        let url = server.join("api")?;
        let response = client.get(url).send().await?;
        Ok(response)
    }

    /*
    /// Get the URL for a changes event source feed.
    pub fn changes_feed_url(
        server: Url,
        signer: BoxedSigner,
    ) -> impl Future<Output = Result<Url>> + 'static {
        use sos_sdk::crypto::csprng;
        async move {
            let message: [u8; 32] = csprng().gen();
            let token = encode_signature(signer.sign(&message).await?)?;
            let message = hex::encode(&message);
            let mut url = server.join("/api/changes")?;
            url.query_pairs_mut()
                .append_pair("message", &message)
                .append_pair("token", &token);
            Ok(url)
        }
    }

    /// Get an event source for the changes feed.
    #[cfg(not(target_arch = "wasm32"))]
    async fn events(server: Url, signer: BoxedSigner) -> Result<EventSource> {
        let url = RequestClient::changes_feed_url(server, signer).await?;
        Ok(EventSource::get(url))
    }

    /// Get a stream of change notifications.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn changes(
        server: Url,
        signer: BoxedSigner,
    ) -> Result<ChangeStream> {
        Ok(ChangeStream::new(
            RequestClient::events(server, signer).await?,
        ))
    }
    */
}
