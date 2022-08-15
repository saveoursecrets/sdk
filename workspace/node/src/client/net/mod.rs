//! HTTP transport trait and implementations.

use sos_core::{encode, signer::BinarySignature};

use super::Result;
use web3_signature::Signature;

#[cfg(not(target_arch = "wasm32"))]
pub mod changes;
pub mod request;
pub mod rpc;

pub use request::RequestClient;
pub use rpc::RpcClient;

#[deprecated]
pub(crate) type Challenge = [u8; 32];

pub(crate) fn encode_signature(signature: Signature) -> Result<String> {
    let signature: BinarySignature = signature.into();
    let value = bs58::encode(encode(&signature)?).into_string();
    Ok(value)
}

pub(crate) fn bearer_prefix(signature: &str) -> String {
    format!("Bearer {}", signature)
}
