//! HTTP client helper functions.

use http::StatusCode;
use rand::Rng;
use reqwest::{header::HeaderMap, RequestBuilder, Response};
use std::future::Future;

use sos_core::{
    commit_tree::CommitProof,
    constants::{
        MIME_TYPE_VAULT, X_COMMIT_PROOF, X_MATCH_PROOF, X_SIGNED_MESSAGE,
    },
    decode, encode,
    signer::BoxedSigner,
    vault::Summary,
    Patch,
};
use url::Url;
use uuid::Uuid;

use crate::client::{Error, Result};

use super::{encode_signature};

#[cfg(not(target_arch = "wasm32"))]
use reqwest_eventsource::EventSource;

#[cfg(not(target_arch = "wasm32"))]
use super::changes::ChangeStream;

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

    /// Get the URL for a changes event source feed.
    pub fn changes_feed_url(
        server: Url,
        signer: BoxedSigner,
    ) -> impl Future<Output = Result<Url>> + 'static {
        async move {
            let message: [u8; 32] = rand::thread_rng().gen();
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
}
