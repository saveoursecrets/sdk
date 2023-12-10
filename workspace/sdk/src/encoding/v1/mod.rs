#[cfg(feature = "account")]
mod account;
mod commit;
mod crypto;
mod events;
#[cfg(feature = "recovery")]
mod recovery;
mod secret;
mod signer;
mod timestamp;
mod vault;

///
pub const VERSION: u16 = 1;
