#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

//! Server for the [Save Our Secrets](https://saveoursecrets.com)
//! sync protocol.
//!
//! If the `listen` feature is enabled the server is compiled
//! with support for sending change notifications over
//! a websocket connection.

mod server;
pub use server::*;
