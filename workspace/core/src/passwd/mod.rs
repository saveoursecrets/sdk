//! Generate and change passwords.
mod change;
pub mod generator;

pub use change::ChangePassword;
pub use generator::diceware;
