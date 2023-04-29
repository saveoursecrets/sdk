use anyhow::Result;
use serial_test::serial;
use std::path::PathBuf;

use sos_core::{
    passwd::diceware::generate_passphrase, secrecy::ExposeSecret,
};

use rexpect::spawn;

#[tokio::test]
#[serial]
async fn integration_command_line() -> Result<()> {
    let account_name = "mock-account";
    let (password, _) = generate_passphrase()?;

    let cache_dir = PathBuf::from("target/command_line_test");
    if cache_dir.exists() {
        std::fs::remove_dir_all(&cache_dir)?;
    }
    std::fs::create_dir_all(&cache_dir)?;

    let cache_dir = cache_dir.canonicalize()?;
    std::env::set_var("SOS_CACHE", cache_dir);

    let is_coverage = std::env::var("COVERAGE_BINARIES").is_ok();
    let exe = if is_coverage {
        PathBuf::from(std::env::var("COVERAGE_BINARIES")?)
            .join("sos")
            .to_string_lossy()
            .into_owned()
    } else {
        "target/debug/sos".to_owned()
    };
    let cmd = format!("{} account new {}", exe, account_name);
    let mut p = spawn(&cmd, None)?;
    p.exp_regex("2[)] Choose a password")?;
    p.send_line("2")?;
    p.exp_regex("Password:")?;
    p.send_line(password.expose_secret())?;
    p.exp_regex("Confirm password:")?;
    p.send_line(password.expose_secret())?;
    p.exp_regex("you want to create a new account")?;
    p.send_line("y")?;
    p.exp_eof()?;

    std::env::remove_var("SOS_CACHE");
    Ok(())
}
