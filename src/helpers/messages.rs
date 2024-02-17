use terminal_banner::colored::Colorize;

const TICK: &str = "✓";
const ERROR: &str = "Error:";

/// Print a success message.
pub fn success(msg: impl AsRef<str>) {
    let out = format!("{} {}", msg.as_ref().green(), TICK.green());
    println!("{}", out);
}

/// Print an error message for failure.
pub fn fail(msg: impl AsRef<str>) {
    let out = format!("{} {}", ERROR.red(), msg.as_ref());
    println!("{}", out);
}
