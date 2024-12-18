//! Proxy to an IPC server using length-prefixed JSON encoding
//! read from stdin and written to stdout.
//!
//! Used to support the native messaging API provided
//! by browser extensions.

/// Body size limit before breaking into chunks.
pub const CHUNK_LIMIT: usize = 256 * 1024;
/// Size of each chunk.
pub const CHUNK_SIZE: usize = 128 * 1024;

#[cfg(feature = "extension-helper-client")]
pub mod client;
#[cfg(feature = "extension-helper-server")]
pub mod server;
