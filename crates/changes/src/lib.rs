//! Local socket change notification producer and consumer.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

mod error;
pub use error::Error;

#[cfg(feature = "changes-consumer")]
pub mod consumer;
#[cfg(feature = "changes-producer")]
pub mod producer;

pub(crate) type Result<T> = std::result::Result<T, Error>;

use std::path::PathBuf;

const SOCKS: &str = "socks";
const SOCK_EXT: &str = "sock";

/// Socket file.
pub(crate) struct SocketFile(PathBuf);

impl From<PathBuf> for SocketFile {
    fn from(value: PathBuf) -> Self {
        Self(value)
    }
}

impl AsRef<PathBuf> for SocketFile {
    fn as_ref(&self) -> &PathBuf {
        &self.0
    }
}

impl Drop for SocketFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Standard path for a consumer socket file.
#[cfg(feature = "changes-consumer")]
pub fn socket_file(paths: &sos_core::Paths) -> Result<PathBuf> {
    let socks = paths.documents_dir().join(SOCKS);
    if !socks.exists() {
        std::fs::create_dir(&socks)?;
    }
    let pid = std::process::id();
    let mut path = socks.join(pid.to_string());
    path.set_extension(SOCK_EXT);
    Ok(path)
}

/// Find active socket files for a producer.
#[cfg(feature = "changes-producer")]
pub fn find_active_sockets(paths: &sos_core::Paths) -> Result<Vec<PathBuf>> {
    let socks = paths.documents_dir().join(SOCKS);
    if socks.exists() {
        todo!();
    } else {
        Ok(Vec::new())
    }
}
