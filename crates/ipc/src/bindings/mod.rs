use sos_net::sdk::prelude::PublicIdentity;

mod protocol;
mod request;
mod response;
pub use protocol::*;
pub use request::*;

/// List of accounts.
pub type AccountsList = Vec<(PublicIdentity, bool)>;
