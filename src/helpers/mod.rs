use std::borrow::Cow;
use terminal_banner::{Banner, Padding};

pub(crate) mod account;
pub(crate) mod editor;
pub(crate) mod readline;
pub(crate) mod secret;

pub(crate) fn display_passphrase(heading: &str, passphrase: &str) {
    let banner = Banner::new()
        .padding(Padding::one())
        .text(Cow::from(heading))
        .text(Cow::from(passphrase))
        .render();
    println!("{}", banner);
}
