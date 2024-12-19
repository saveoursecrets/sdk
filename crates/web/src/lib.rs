#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Web accounts for the [Save Our Secrets SDK](https://saveoursecrets.com/) intended to be used in webassembly bindings.

use sos_sdk::prelude::{Account, AccountSwitcher};

mod error;

mod linked_account;
pub use linked_account::*;

/// Account switcher for linked accounts.
pub type LinkedAccountSwitcher = AccountSwitcher<
    LinkedAccount,
    <LinkedAccount as Account>::NetworkResult,
    <LinkedAccount as Account>::Error,
>;

pub use error::Error;

/// Result type for the library.
pub type Result<T> = std::result::Result<T, Error>;
