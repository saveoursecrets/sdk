//! Web accounts for the [Save Our Secrets SDK](https://saveoursecrets.com/) intended to be used in webassembly bindings.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

use sos_account::{Account, AccountSwitcher};

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
pub(crate) type Result<T> = std::result::Result<T, Error>;
