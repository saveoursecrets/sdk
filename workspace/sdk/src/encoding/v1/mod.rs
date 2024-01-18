#[cfg(feature = "audit")]
mod audit;
mod commit;
mod crypto;
mod events;
#[cfg(feature = "recovery")]
mod recovery;
mod secret;
mod signer;
#[cfg(feature = "sync")]
mod sync;
mod timestamp;
mod vault;

///
pub const VERSION: u16 = 1;

