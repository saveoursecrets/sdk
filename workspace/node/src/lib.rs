#![deny(missing_docs)]
//! Library for network communication.

#[cfg(not(target_arch = "wasm32"))]
use std::{path::PathBuf, sync::RwLock};

#[cfg(not(target_arch = "wasm32"))]
use once_cell::sync::Lazy;

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

#[cfg(not(target_arch = "wasm32"))]
static CACHE_DIR: Lazy<RwLock<Option<PathBuf>>> =
    Lazy::new(|| RwLock::new(None));

/// Get the default root directory used for caching client data.
///
/// If the `SOS_CACHE_DIR` environment variable is set it is used.
///
/// Otherwise is an explicit directory has been set using `set_cache_dir()`
/// then that will be used.
///
/// Finally if no environment variable or explicit directory has been
/// set then a path will be computed by platform convention.
#[cfg(not(target_arch = "wasm32"))]
pub fn cache_dir() -> Option<PathBuf> {
    let dir = if let Some(env_cache_dir) = std::env::var("SOS_CACHE_DIR").ok() {

        println!("USING CACHE_DIR");
        Some(PathBuf::from(env_cache_dir))
    } else {
        let reader = CACHE_DIR.read().unwrap();
        if reader.is_some() {
            Some(reader.as_ref().unwrap().to_path_buf())
        } else {
            println!("USING default or fallback!");
            default_storage_dir().or(fallback_storage_dir())
        }
    };

    // Try to ensure the directory exists
    dir.and_then(|d| {
        if !d.exists() {
            let _ = std::fs::create_dir_all(&d);
        }
        Some(d)
    })
}

/// Set an explicit cache directory.
#[cfg(not(target_arch = "wasm32"))]
pub fn set_cache_dir(path: PathBuf) {
    let mut writer = CACHE_DIR.write().unwrap();
    *writer = Some(path);
}

#[cfg(target_os = "macos")]
fn default_storage_dir() -> Option<PathBuf> {
    use sos_core::constants::BUNDLE_ID;
    dirs::home_dir().and_then(|v| {
        let d = v
            .join("Library")
            .join("Containers")
            .join(BUNDLE_ID)
            .join("Data")
            .join("Documents");
        Some(d)
    })
}

#[cfg(target_os = "ios")]
fn default_storage_dir() -> Option<PathBuf> {
    // FIXME: compute according to provider_path
    fallback_storage_dir()
}

#[cfg(target_os = "android")]
fn default_storage_dir() -> Option<PathBuf> {
    // FIXME: compute according to provider_path
    fallback_storage_dir()
}

#[cfg(target_os = "linux")]
fn default_storage_dir() -> Option<PathBuf> {
    // FIXME: compute according to provider_path
    fallback_storage_dir()
}

#[cfg(target_os = "windows")]
fn default_storage_dir() -> Option<PathBuf> {
    use sos_core::constants::BUNDLE_ID;
    dirs::home_dir().and_then(|v| {
        let d = v
            .join("AppData")
            .join("Local")
            .join(BUNDLE_ID);
        Some(d)
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn fallback_storage_dir() -> Option<PathBuf> {
    use sos_core::constants::BUNDLE_ID;
    dirs::data_local_dir().and_then(|dir| Some(dir.join(BUNDLE_ID)))
}
