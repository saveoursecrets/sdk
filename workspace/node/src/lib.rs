pub mod client;
mod error;

pub use error::Error;
pub type Result<T> = std::result::Result<T, error::Error>;

pub use client::account::{
    create_account, create_signing_key, login, ClientCredentials, ClientKey,
};
pub use client::cache::{
    ClientCache, FileCache, SyncInfo, SyncKind, SyncStatus,
};
pub use client::http_client::Client;
pub use client::{ClientBuilder, PassphraseReader};
