use anyhow::Result;
use sos_database::open_memory;

/// Print SQLite compile options.
#[tokio::main]
pub async fn main() -> Result<()> {
    let client = open_memory().await?;
    client
        .conn(|conn| {
            let mut stmt = conn.prepare("PRAGMA compile_options")?;
            let compile_options_iter =
                stmt.query_map([], |row| row.get::<_, String>(0))?;
            for option in compile_options_iter {
                println!("{}", option?);
            }
            Ok(())
        })
        .await?;
    Ok(())
}
