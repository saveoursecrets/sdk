use anyhow::{anyhow, Result};
use std::{
    borrow::Cow::{self, Borrowed, Owned},
    io::{self, Read},
};

use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::{ColorMode, Editor};

use rustyline::{
    Cmd, ConditionalEventHandler, Event, EventContext, EventHandler, KeyCode,
    KeyEvent, Modifiers, RepeatCount,
};

use rustyline_derive::{Completer, Helper, Hinter, Validator};

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
pub fn read_password(prompt: &str) -> Result<String> {
    let h = MaskingHighlighter { masking: true };
    let mut rl = Editor::new();
    rl.set_helper(Some(h));
    rl.set_color_mode(ColorMode::Forced);
    rl.set_auto_add_history(false);

    // NOTE: trim any trailing newline is a quick hack
    // NOTE: for pasting
    let passwd = rl.readline(prompt)?.trim_end_matches('\n').to_string();

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

struct FilteringEventHandler;
impl ConditionalEventHandler for FilteringEventHandler {
    fn handle(
        &self,
        evt: &Event,
        _: RepeatCount,
        _: bool,
        _: &EventContext,
    ) -> Option<Cmd> {
        if let Some(KeyEvent(KeyCode::Char(c), m)) = evt.get(0) {
            if m.contains(Modifiers::CTRL)
                && *c == 'D'
            {
                println!("Got EOF Ctrl+d");
                Some(Cmd::Abort)
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// Read a multi-line string.
pub fn read_multiline(prompt: Option<&str>) -> Result<Option<String>> {
    let mut rl = rustyline::Editor::<()>::new();
    rl.bind_sequence(
        Event::Any,
        EventHandler::Conditional(Box::new(FilteringEventHandler)),
    );

    let readline = rl.readline(prompt.unwrap_or(DEFAULT_PROMPT));
    let mut value = String::new();
    loop {
        match readline {
            Ok(ref line) => {
                value.push_str(line);
                value.push('\n');
            }
            Err(e) => {
                println!("Got error {:#?}", e);
                match e {
                    ReadlineError::Eof => {
                        println!("Got EOF!");
                        return Ok(Some(value));
                    }
                    ReadlineError::Interrupted => return Ok(None),
                    _ => return Err(anyhow!(e)),
                }
            }
        }
    }
}
