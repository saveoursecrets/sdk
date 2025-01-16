//! Extra functions for [local accounts](https://docs.rs/sos-account/latest/sos_account/) in the [Save Our Secrets](https://saveoursecrets.com) SDK.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

#[cfg(feature = "security-report")]
pub mod security_report;
