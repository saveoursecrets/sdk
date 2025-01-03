//! Prelude re-exports common types.
#[cfg(feature = "audit")]
pub use crate::audit::*;
pub use crate::constants::*;
pub use crate::device::*;
pub use crate::events::*;
pub use crate::identity::*;

pub use sos_core::{crypto::*, decode, encode, UtcDateTime};
pub use sos_password::diceware::generate_passphrase;
pub use sos_signer::ecdsa::Address;
pub use sos_vault::secret::*;
pub use sos_vault::*;
pub use sos_vfs as vfs;

// Ensure top-level versions take precedence
pub use crate::{error::ErrorExt, Error, Paths, Result};
