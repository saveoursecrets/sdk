//! Proxy to an IPC server using length-prefixed JSON encoding
//! read from stdin and written to stdout.
//!
//! Used to support the native messaging API provided
//! by browser extensions.

#[cfg(feature = "native-bridge-client")]
pub mod client;
#[cfg(feature = "native-bridge-server")]
pub mod server;
