use std::{
    borrow::Cow::{self, Borrowed, Owned},
    io::{self, Read},
};

use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::{ColorMode, Editor};

use rustyline_derive::{Completer, Helper, Hinter, Validator};

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
pub fn read_password(prompt: Option<&str>) -> Result<String> {
    let h = MaskingHighlighter { masking: true };
    let mut rl = Editor::new();
    rl.set_helper(Some(h));
    rl.set_color_mode(ColorMode::Forced);
    rl.set_auto_add_history(false);

    // NOTE: trim any trailing newline is a quick hack
    // NOTE: for pasting
    let passwd = rl
        .readline(prompt.unwrap_or("Password: "))?
        .trim_end_matches('\n')
        .to_string();

    Ok(passwd)
}

/// Read a passphrase from stdin passed into the program.
pub fn read_stdin() -> Result<Option<String>> {
    if atty::isnt(atty::Stream::Stdin) {
        let mut buffer = Vec::new();
        io::stdin().lock().read_to_end(&mut buffer)?;
        Ok(Some(std::str::from_utf8(&buffer)?.trim().to_string()))
    } else {
        Ok(None)
    }
}

/// Read a multi-line string.
pub fn read_multiline(prompt: Option<&str>) -> Result<Option<String>> {
    let mut rl = rustyline::Editor::<()>::new();

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

/// Read a line and invoke the shell callback.
pub fn read_shell<H>(
    mut handler: H,
    prompt: impl Fn() -> String,
) -> Result<String>
where
    H: FnMut(String),
{
    let mut rl = rustyline::Editor::<()>::new();
    loop {
        let prompt_value = prompt();
        let readline = rl.readline(&prompt_value);
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                handler(line);
            }
            Err(e) => return Err(Error::Readline(e)),
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

fn read_line_value(prompt: Option<&str>, allows_empty: bool) -> Result<String> {
    let mut rl = rustyline::Editor::<()>::new();
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
    let mut rl = rustyline::Editor::<()>::new();
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
    let mut rl = rustyline::Editor::<()>::new();
    let readline = rl.readline(prompt.unwrap_or(DEFAULT_PROMPT));
    match readline {
        Ok(ref line) => {
            let flag = line == "y" || line == "yes";
            Ok(flag)
        }
        Err(e) => Err(Error::Readline(e)),
    }
}
