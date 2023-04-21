use std::borrow::Cow;
use terminal_banner::{Banner, Padding};

mod account;
pub(crate) mod cli;
mod monitor;
pub mod readline;
mod shell;

pub use cli::run;
pub use shell::ShellState;

pub(crate) fn display_passphrase(heading: &str, passphrase: &str) {
    let banner = Banner::new()
        .padding(Padding::one())
        .text(Cow::from(heading))
        .text(Cow::from(passphrase))
        .render();
    println!("{}", banner);
}

pub use account::{local_signup, sign_in, switch, StdinPassphraseReader};
pub use monitor::monitor;
pub use shell::exec;
