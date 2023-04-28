use std::borrow::Cow::{self, Borrowed, Owned};

use rustyline::{
    config::Configurer, error::ReadlineError, highlight::Highlighter,
    history::MemHistory, ColorMode, Editor,
};
use rustyline_derive::{Completer, Helper, Hinter, Validator};
use sos_core::secrecy::{Secret, SecretString};

use crate::{Error, Result};

const DEFAULT_PROMPT: &str = ">> ";

#[derive(Completer, Helper, Hinter, Validator)]
struct MaskingHighlighter {
    masking: bool,
}

impl Highlighter for MaskingHighlighter {
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        use unicode_width::UnicodeWidthStr;
        if self.masking {
            Owned("*".repeat(line.width()))
        } else {
            Borrowed(line)
        }
    }

    fn highlight_char(&self, _line: &str, _pos: usize) -> bool {
        self.masking
    }
}

/// Read a passphrase from stdin prompt.
pub fn read_password(prompt: Option<&str>) -> Result<SecretString> {
    #[cfg(any(test, debug_assertions))]
    if let Ok(password) = std::env::var("SOS_PASSWORD") {
        return Ok(SecretString::new(password));
    }

    let h = MaskingHighlighter { masking: true };
    let mut rl = Editor::new()?;
    rl.set_helper(Some(h));
    rl.set_color_mode(ColorMode::Forced);
    rl.set_auto_add_history(false);

    // NOTE: trim any trailing newline is a quick hack
    // NOTE: for pasting
    let passwd = rl
        .readline(prompt.unwrap_or("Password: "))?
        .trim_end_matches('\n')
        .to_string();

    Ok(Secret::new(passwd))
}

pub(crate) fn basic_editor() -> Result<Editor<(), MemHistory>> {
    Ok(Editor::<(), MemHistory>::with_history(
        Default::default(),
        MemHistory::new(),
    )?)
}

/// Read a multi-line string.
pub fn read_multiline(prompt: Option<&str>) -> Result<Option<String>> {
    let mut rl = basic_editor()?;

    let mut value = String::new();
    loop {
        let readline = rl.readline(prompt.unwrap_or(DEFAULT_PROMPT));
        match readline {
            Ok(ref line) => {
                value.push_str(line);
                value.push('\n');
            }
            Err(e) => match e {
                ReadlineError::Eof => {
                    return Ok(Some(value));
                }
                ReadlineError::Interrupted => return Ok(None),
                _ => return Err(Error::Readline(e)),
            },
        }
    }
}

pub fn read_line_allow_empty(prompt: Option<&str>) -> Result<String> {
    read_line_value(prompt, true)
}

/// Read a string that may not be the empty string.
pub fn read_line(prompt: Option<&str>) -> Result<String> {
    read_line_value(prompt, false)
}

fn read_line_value(
    prompt: Option<&str>,
    allows_empty: bool,
) -> Result<String> {
    let mut rl = basic_editor()?;
    loop {
        let readline = rl.readline(prompt.unwrap_or(DEFAULT_PROMPT));
        match readline {
            Ok(line) => {
                if allows_empty {
                    return Ok(line);
                }

                if !line.trim().is_empty() {
                    return Ok(line);
                }
            }
            Err(e) => return Err(Error::Readline(e)),
        }
    }
}

/// Read an optional string.
pub fn read_option(prompt: Option<&str>) -> Result<Option<String>> {
    let mut rl = basic_editor()?;
    let readline = rl.readline(prompt.unwrap_or(DEFAULT_PROMPT));
    match readline {
        Ok(line) => {
            if !line.trim().is_empty() {
                Ok(Some(line))
            } else {
                Ok(None)
            }
        }
        Err(e) => Err(Error::Readline(e)),
    }
}

/// Read a flag value (y/n).
pub fn read_flag(prompt: Option<&str>) -> Result<bool> {
    let mut rl = basic_editor()?;
    let readline = rl.readline(prompt.unwrap_or(DEFAULT_PROMPT));
    match readline {
        Ok(ref line) => {
            let flag = line == "y" || line == "yes";
            Ok(flag)
        }
        Err(e) => Err(Error::Readline(e)),
    }
}

/// Represents a choice message and associated type.
pub struct Choice<'a, T>(pub Cow<'a, str>, pub T);

/// Choose from a list of options.
pub fn choose<'a, T>(
    prompt: Option<&str>,
    options: &'a [Choice<T>],
) -> Result<Option<&'a T>> {
    for (index, option) in options.iter().enumerate() {
        println!("{}) {}", index + 1, option.0);
    }

    let value = read_line(prompt)?;
    match value.parse::<usize>() {
        Ok(num) => {
            let num = if num > 0 { num - 1 } else { num };
            Ok(options.get(num).as_ref().map(|result| &result.1))
        }
        Err(_) => Ok(None),
    }
}
