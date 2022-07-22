//! HTTP transport trait and implementations.
use http::StatusCode;
use sos_core::{
    address::AddressStr, commit_tree::CommitProof, encode,
    signer::BinarySignature, vault::Summary, Patch,
};

use super::Result;
use uuid::Uuid;
use web3_signature::Signature;

#[cfg(not(target_arch = "wasm32"))]
pub mod changes;
pub mod request;
pub use request::RequestClient;

pub(crate) type Challenge = [u8; 32];

pub(crate) fn encode_signature(signature: Signature) -> Result<String> {
    let signature: BinarySignature = signature.into();
    let value = bs58::encode(encode(&signature)?).into_string();
    Ok(value)
}

pub(crate) fn bearer_prefix(signature: &str) -> String {
    format!("Bearer {}", signature)
}
