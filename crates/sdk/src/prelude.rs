//! Prelude re-exports common types.
#[cfg(feature = "audit")]
pub use crate::audit::*;
pub use crate::constants::*;
pub use crate::crypto::*;
pub use crate::device::*;
pub use crate::events::*;
pub use crate::formats::*;
pub use crate::identity::*;
pub use crate::passwd::*;
pub use crate::signer::ecdsa::Address;
pub use crate::vault::secret::*;
pub use crate::vault::*;
pub use crate::vfs;
pub use crate::{
    decode, encode, passwd::diceware::generate_passphrase, Paths, UtcDateTime,
};

#[cfg(feature = "recovery")]
pub use crate::recovery::*;

// Ensure top-level versions take precedence
pub use crate::{error::ErrorExt, Error, Result};
