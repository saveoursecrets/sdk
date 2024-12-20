//! Access to the native system clipboard.
use crate::Result;
use std::{borrow::Cow, sync::Arc};
use tokio::{
    sync::Mutex,
    time::{sleep, Duration},
};
use zeroize::Zeroize;

/// Native system clipboard.
#[derive(Clone)]
pub struct Clipboard {
    timeout_seconds: u16,
}

impl Clipboard {
    /// Create a native clipboard using the default
    /// timeout of 90 seconds.
    pub fn new() -> Result<Self> {
        Self::new_timeout(90)
    }

    /// Create a native clipboard with a timeout.
    pub fn new_timeout(timeout_seconds: u16) -> Result<Self> {
        Ok(Self { timeout_seconds })
    }

    /// Fetches UTF-8 text from the clipboard and returns it.
    ///
    /// # Errors
    ///
    /// Returns error if clipboard is empty or contents are not UTF-8 text.
    pub async fn get_text(&self) -> Result<String> {
        unimplemented!();
    }

    /// Places the text onto the clipboard. Any valid UTF-8
    /// string is accepted.
    ///
    /// # Errors
    ///
    /// Returns error if text failed to be stored on the clipboard.
    pub async fn set_text<'a, T: Into<Cow<'a, str>>>(
        &self,
        text: T,
    ) -> Result<()> {
        unimplemented!();
    }

    /// Clears any contents that may be present from the
    /// platform's default clipboard, regardless of the format of the data.
    ///
    /// # Errors
    ///
    /// Returns error on Windows or Linux if clipboard cannot be cleared.
    pub async fn clear(&self) -> Result<()> {
        unimplemented!();
    }

    /// Places text on to the clipboard and sets a timeout to clear
    /// the text from the clipboard.
    ///
    /// The text is only cleared if the clipboard contents match the
    /// initial value to allow for the user changing the clipboard
    /// content elsewhere whilst the the timeout is active.
    pub async fn set_text_timeout<'a, T: Into<Cow<'a, str>>>(
        &self,
        text: T,
    ) -> Result<()> {
        unimplemented!();
    }
}
