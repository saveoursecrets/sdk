use std::borrow::Cow;
use terminal_banner::{Banner, Padding};

mod account;
mod error;
mod monitor;
mod shell;

pub type Result<T> = std::result::Result<T, error::Error>;

pub use shell::ShellState;

pub(crate) fn display_passphrase(heading: &str, passphrase: &str) {
    let banner = Banner::new()
        .padding(Padding::one())
        .text(Cow::from(heading))
        .text(Cow::from(passphrase))
        .render();
    println!("{}", banner);
}

pub use account::{local_signup, signup, switch, StdinPassphraseReader};
pub use error::Error;
pub use monitor::monitor;
pub use shell::exec;
