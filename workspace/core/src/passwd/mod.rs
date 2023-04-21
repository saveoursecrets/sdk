//! Generate and change passwords.
mod change;
pub mod generator;

pub use generator::diceware;
pub use change::ChangePassword;
