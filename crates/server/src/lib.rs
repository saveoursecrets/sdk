#![allow(clippy::result_large_err)]
#![allow(clippy::module_inception)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

//! Reference server for [Save Our Secrets](https://saveoursecrets.com).
//!
//! If the `listen` feature is enabled the server is compiled
//! with support for sending change notifications over
//! a websocket connection.

// mod error;
mod server;

pub use server::*;
