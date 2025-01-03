#[cfg(feature = "audit")]
mod audit;
#[deprecated]
mod events;
#[deprecated]
mod secret;
#[deprecated]
mod vault;

///
pub const VERSION: u16 = 1;
