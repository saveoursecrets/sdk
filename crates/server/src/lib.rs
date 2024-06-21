#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

//! Server for the [Save Our Secrets](https://saveoursecrets.com)
//! sync protocol.
//!
//! If the `listen` feature is enabled the server is compiled
//! with support for sending change notifications over
//! a websocket connection.

mod api_docs;
mod authenticate;
mod backend;
mod config;
mod error;
mod handlers;
mod server;
mod storage;

pub use error::Error;

/// Result type for the server module.
pub type Result<T> = std::result::Result<T, error::Error>;

pub use backend::Backend;
pub use config::*;
pub use server::{Server, ServerBackend, ServerState, State};

#[cfg(feature = "files")]
pub use server::ServerTransfer;
