#![deny(missing_docs)]
//! Library for network communication.
use std::path::PathBuf;

extern crate sha3;

#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "agent-client", feature = "agent-server")
))]
pub mod agent;
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "server")]
pub mod server;

mod error;
pub mod session;
pub mod sync;

/// Result type for the node module.
pub type Result<T> = std::result::Result<T, error::Error>;
pub use error::Error;

const DIR: &str = "SaveOurSecrets";

/// Get the default root directory used for caching client data.
///
/// If the `CACHE_DIR` environment variable is set it is used
/// instead of the default location.
pub fn cache_dir() -> Option<PathBuf> {
    if let Some(env_cache_dir) = std::env::var("CACHE_DIR").ok() {
        Some(PathBuf::from(env_cache_dir))
    } else {
        dirs::data_local_dir().and_then(|v| {
            let d = v.join(DIR);
            if !d.exists() {
                let _ = std::fs::create_dir(&d);
            }
            Some(d)
        })
    }
}
