#[cfg(feature = "audit")]
mod audit;
#[deprecated]
mod events;
mod secret;
mod signer;
mod vault;

///
pub const VERSION: u16 = 1;
