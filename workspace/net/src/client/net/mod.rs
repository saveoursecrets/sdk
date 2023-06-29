//! HTTP transport trait and implementations.

use sos_sdk::{
    encode,
    signer::ecdsa::{BinarySignature, BoxedEcdsaSigner},
};

use url::Url;
use uuid::Uuid;
use web3_signature::Signature;

use super::Result;

#[cfg(not(target_arch = "wasm32"))]
pub mod changes;

mod rpc;
pub use rpc::{MaybeRetry, RpcClient};

const AUTHORIZATION: &str = "authorization";

pub(crate) async fn encode_signature(signature: Signature) -> Result<String> {
    let signature: BinarySignature = signature.into();
    let value = bs58::encode(encode(&signature).await?).into_string();
    Ok(value)
}

pub(crate) fn bearer_prefix(signature: &str) -> String {
    format!("Bearer {}", signature)
}

/// Get the URI for a websocket connection.
fn websocket_uri(
    endpoint: Url,
    //request: Vec<u8>,
    bearer: String,
    public_key: &[u8],
) -> String {
    format!(
        "{}?bearer={}&public_key={}",
        endpoint,
        //bs58::encode(&request).into_string(),
        bearer,
        hex::encode(public_key),
    )
}

/// Gets the endpoint URL for a websocket connection.
///
/// The `remote` must be an HTTP/S URL; it's scheme will
/// be switched to `ws` or `wss` as appropiate and the path
/// for the changes endpoint will be added.
///
/// Panics if the remote scheme is invalid or it failed to
/// set the scheme on the endpoint.
fn changes_endpoint_url(remote: &Url) -> Result<Url> {
    let mut endpoint = remote.join("api/changes")?;
    let scheme = if endpoint.scheme() == "http" {
        "ws"
    } else if endpoint.scheme() == "https" {
        "wss"
    } else {
        panic!("bad url scheme for websocket connection, requires http(s)");
    };
    endpoint
        .set_scheme(scheme)
        .expect("failed to set websocket scheme");
    Ok(endpoint)
}

/// Get the URI for a websocket changes connection.
pub async fn changes_uri(
    remote: &Url,
    signer: &BoxedEcdsaSigner,
    public_key: &[u8],
) -> Result<String> {
    let endpoint = changes_endpoint_url(remote)?;
    let bearer = encode_signature(signer.sign(&public_key).await?).await?;
    //let message = encode(&aead).await?;
    let uri = websocket_uri(endpoint, bearer, public_key);
    Ok(uri)
}
