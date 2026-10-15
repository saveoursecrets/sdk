//! Server for the [Save Our Secrets](https://saveoursecrets.com)
//! sync protocol.
//!
//! If the `listen` feature is enabled the server is compiled
//! with support for sending change notifications over
//! a websocket connection.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(clippy::result_large_err)]

mod api_docs;
mod authenticate;
mod backend;
mod config;
mod error;
mod handlers;
mod server;

pub use error::Error;

/// Result type for the server module.
#[doc(hidden)]
pub type Result<T> = std::result::Result<T, error::Error>;

pub use backend::Backend;
pub use config::*;
pub use server::{Server, ServerBackend, ServerState, ServerTransfer, State};
