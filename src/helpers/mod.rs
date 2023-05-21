use crate::Result;
use arboard::Clipboard;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::borrow::Cow;
use terminal_banner::{Banner, Padding};

pub(crate) mod account;
pub(crate) mod editor;
pub(crate) mod readline;
pub(crate) mod secret;

/// Global clipboard singleton.
pub(crate) static CLIPBOARD: Lazy<Mutex<Option<Clipboard>>> =
    Lazy::new(|| Mutex::new(Clipboard::new().ok()));

pub(crate) fn set_clipboard_text(text: &str) -> Result<bool> {
    let mut clipboard = CLIPBOARD.lock();
    if let Some(clipboard) = clipboard.as_mut() {
        clipboard.set_text(text)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub(crate) fn display_passphrase(heading: &str, passphrase: &str) {
    let banner = Banner::new()
        .padding(Padding::one())
        .text(Cow::from(heading))
        .text(Cow::from(passphrase))
        .render();
    println!("{}", banner);
}
