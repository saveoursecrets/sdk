//! HTTP transport trait and implementations.
use sos_sdk::{
    encode,
    signer::{
        ecdsa::{BinaryEcdsaSignature, Signature},
        ed25519::{BinaryEd25519Signature, Signature as Ed25519Signature},
    },
};

use super::Result;

mod http;
#[cfg(feature = "listen")]
mod websocket;

pub use http::HttpClient;
#[cfg(feature = "listen")]
pub use websocket::{changes, connect, ListenOptions, WebSocketHandle};

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

pub(crate) fn bearer_prefix(
    account_signature: &str,
    device_signature: Option<&str>,
) -> String {
    if let Some(device_signature) = device_signature {
        format!("Bearer {}.{}", account_signature, device_signature)
    } else {
        format!("Bearer {}", account_signature)
    }
}
