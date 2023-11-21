mod commit;
mod crypto;
mod events;
#[cfg(feature = "recovery")]
mod recovery;
mod secret;
mod signer;
mod timestamp;
mod vault;

/// Version number for this encoding.
pub const VERSION: u16 = 1;
