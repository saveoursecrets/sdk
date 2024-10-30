use sos_ipc::Result;
use tokio::io::{AsyncBufReadExt, BufReader};
use serde_json::Value;
use std::io::Write;

#[tokio::main]
pub async fn main() -> Result<()> {
    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = std::io::stdout();

    loop {
        let mut input = String::new();
        if stdin.read_line(&mut input).await? == 0 {
            break;
        }

        let json: Value = match serde_json::from_str(&input.trim()) {
            Ok(value) => value,
            Err(e) => {
                eprintln!("Error parsing JSON: {}", e);
                continue;
            }
        };

        // Process the JSON input (you can replace this with your actual processing logic)
        let output = format!("Processed JSON: {}", json);

        writeln!(stdout, "{}", output)?;
        stdout.flush()?;
    }

    Ok(())
}
