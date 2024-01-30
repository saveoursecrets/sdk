use crate::Result;
use arboard::Clipboard;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use terminal_banner::{Banner, Padding};
use tokio::sync::broadcast::Sender;

pub(crate) mod account;
pub(crate) mod editor;
pub(crate) mod readline;
pub(crate) mod secret;

pub use account::USER;

/// Is a progress monitor running?
///
/// Used for ctrlc handling to quit the progress monitor
/// before quitting the shell.
pub(crate) static PROGRESS_MONITOR: Lazy<Mutex<Option<Sender<()>>>> =
    Lazy::new(|| Mutex::new(None));

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
        .text(heading.into())
        .text(passphrase.into())
        .render();
    println!("{}", banner);
}
