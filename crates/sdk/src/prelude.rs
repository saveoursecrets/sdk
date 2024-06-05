//! Prelude re-exports common types.
#[cfg(all(feature = "account", feature = "archive"))]
pub use crate::account::archive::*;
#[cfg(all(feature = "account", feature = "preferences"))]
pub use crate::account::preferences::*;
#[cfg(all(feature = "account", feature = "security-report"))]
pub use crate::account::security_report::*;
#[cfg(all(feature = "account", feature = "system-messages"))]
pub use crate::account::system_messages::*;
#[cfg(feature = "account")]
pub use crate::account::*;
#[cfg(feature = "audit")]
pub use crate::audit::*;
pub use crate::commit::*;
pub use crate::constants::*;
pub use crate::crypto::*;
#[cfg(feature = "device")]
pub use crate::device::*;
pub use crate::events::*;
pub use crate::formats::*;
pub use crate::identity::*;
pub use crate::integrity::*;
#[cfg(feature = "migrate")]
pub use crate::migrate::export::*;
#[cfg(feature = "migrate")]
pub use crate::migrate::import::*;
#[cfg(feature = "migrate")]
pub use crate::migrate::*;
pub use crate::signer::ecdsa::Address;
#[cfg(feature = "files")]
pub use crate::storage::files::*;
#[cfg(feature = "search")]
pub use crate::storage::search::*;
pub use crate::storage::*;
#[cfg(feature = "sync")]
pub use crate::sync::*;
pub use crate::vault::secret::*;
pub use crate::vault::*;
pub use crate::vfs;
pub use crate::{
    decode, encode, passwd::diceware::generate_passphrase, Paths, UtcDateTime,
};

#[cfg(feature = "recovery")]
pub use crate::recovery::*;

// Ensure top-level versions take precedence
pub use crate::{Error, Result};
