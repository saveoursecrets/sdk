mod commit;
mod crypto;
mod events;
mod patch;
#[cfg(feature = "recovery")]
mod recovery;
mod rpc;
mod secret;
mod signer;
mod timestamp;
mod vault;

/// Version number for this encoding.
pub const VERSION: u16 = 1;
