//! HTTP transport trait and implementations.

use sos_sdk::{encode, signer::ecdsa::BinarySignature};

use web3_signature::Signature;

use super::Result;

#[cfg(feature = "listen")]
mod websocket;

mod rpc;

pub use rpc::{MaybeRetry, RpcClient};

#[cfg(feature = "listen")]
pub use websocket::{changes, connect, ListenOptions, WebSocketHandle};

const AUTHORIZATION: &str = "authorization";

pub(crate) async fn encode_signature(signature: Signature) -> Result<String> {
    let signature: BinarySignature = signature.into();
    let value = bs58::encode(encode(&signature).await?).into_string();
    Ok(value)
}

pub(crate) fn bearer_prefix(signature: &str) -> String {
    format!("Bearer {}", signature)
}
