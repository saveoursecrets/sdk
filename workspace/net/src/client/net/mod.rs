//! HTTP transport trait and implementations.

use sos_sdk::{
    encode,
    signer::{
        ecdsa::BinaryEcdsaSignature,
        ed25519::{BinaryEd25519Signature, Signature as Ed25519Signature},
    },
};

use web3_signature::Signature;

use super::Result;

#[cfg(feature = "listen")]
mod websocket;

mod rpc;

pub use rpc::RpcClient;

#[cfg(feature = "listen")]
pub use websocket::{changes, connect, ListenOptions, WebSocketHandle};

const AUTHORIZATION: &str = "authorization";

pub(crate) async fn encode_account_signature(
    signature: Signature,
) -> Result<String> {
    let signature: BinaryEcdsaSignature = signature.into();
    Ok(bs58::encode(encode(&signature).await?).into_string())
}

pub(crate) async fn encode_device_signature(
    signature: Ed25519Signature,
) -> Result<String> {
    let signature: BinaryEd25519Signature = signature.into();
    Ok(bs58::encode(encode(&signature).await?).into_string())
}

pub(crate) fn bearer_prefix(signature: &str) -> String {
    format!("Bearer {}", signature)
}
