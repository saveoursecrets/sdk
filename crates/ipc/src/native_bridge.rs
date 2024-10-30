use serde_json::Value;
use sos_ipc::Result;
use std::io::Write;
use tokio::io::{AsyncReadExt, BufReader};

#[tokio::main]
pub async fn main() -> Result<()> {
    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = std::io::stdout();

    loop {
        // Read the length of the message (u32)
        let length = match stdin.read_u32_le().await {
            Ok(len) => len,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                eprintln!("Error reading message length: {}", e);
                continue;
            }
        };

        // Read the JSON message
        let mut buffer = vec![0u8; length as usize];
        if let Err(e) = stdin.read_exact(&mut buffer).await {
            eprintln!("Error reading message: {}", e);
            continue;
        }

        // Parse the JSON
        let json: Value = match serde_json::from_slice(&buffer) {
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
