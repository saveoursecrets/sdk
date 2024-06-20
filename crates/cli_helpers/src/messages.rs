//! Helper functions to print messages.

use colored::Colorize;

const TICK: &str = "✓";
const INFO: &str = "Info";
const WARN: &str = "Warn";
const ERROR: &str = "Error";

/// Print a success message.
pub fn success(msg: impl AsRef<str>) {
    let out = format!("{} {}", msg.as_ref().green(), TICK.green());
    println!("{}", out);
}

/// Print an error message for failure.
pub fn fail(msg: impl AsRef<str>) {
    let out = format!("{} {}", ERROR.red(), msg.as_ref());
    eprintln!("{}", out);
}

/// Print an info message.
pub fn info(msg: impl AsRef<str>) {
    let out = format!("{} {}", INFO.cyan(), msg.as_ref());
    println!("{}", out);
}

/// Print a warning message.
pub fn warn(msg: impl AsRef<str>) {
    let out = format!("{} {}", WARN.yellow(), msg.as_ref());
    println!("{}", out);
}
