//! HTTP transport trait and implementations.

use sos_sdk::{
    encode,
    mpc::{generate_keypair, Keypair},
    signer::ecdsa::{BinarySignature, BoxedEcdsaSigner},
};

use url::Url;
use web3_signature::Signature;

use super::Result;

#[cfg(not(target_arch = "wasm32"))]
mod websocket;

mod rpc;

pub use rpc::{MaybeRetry, RpcClient};
pub use websocket::{changes, connect, ListenOptions};

const AUTHORIZATION: &str = "authorization";

pub(crate) async fn encode_signature(signature: Signature) -> Result<String> {
    let signature: BinarySignature = signature.into();
    let value = bs58::encode(encode(&signature).await?).into_string();
    Ok(value)
}

pub(crate) fn bearer_prefix(signature: &str) -> String {
    format!("Bearer {}", signature)
}
