//! HTTP transport trait and implementations.

use sos_core::{encode, signer::BinarySignature};

use super::Result;
use web3_signature::Signature;

#[deprecated]
#[cfg(not(target_arch = "wasm32"))]
pub mod changes;

pub mod request;
pub mod rpc;

#[cfg(not(target_arch = "wasm32"))]
pub mod ws_changes;

pub use request::RequestClient;
pub use rpc::RpcClient;

const AUTHORIZATION: &str = "authorization";

pub(crate) fn encode_signature(signature: Signature) -> Result<String> {
    let signature: BinarySignature = signature.into();
    let value = bs58::encode(encode(&signature)?).into_string();
    Ok(value)
}

pub(crate) fn bearer_prefix(signature: &str) -> String {
    format!("Bearer {}", signature)
}
