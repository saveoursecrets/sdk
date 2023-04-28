use anyhow::Result;
use serial_test::serial;
use std::{path::PathBuf, ffi::OsStr, process::Stdio};

use futures::Future;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::process::Command;

use sos_core::{
    passwd::diceware::generate_passphrase, secrecy::ExposeSecret,
};

use sos::cli::run;

use rexpect::spawn;

#[tokio::test]
#[serial]
async fn integration_command_line() -> Result<()> {
    let (password, _) = generate_passphrase()?;
    std::env::set_var("SOS_PASSWORD", password.expose_secret().to_owned());

    let cache_dir = PathBuf::from("target/command_line_test");
    if cache_dir.exists() {
        std::fs::remove_dir_all(&cache_dir)?;
    }
    std::fs::create_dir_all(&cache_dir)?;

    let cache_dir = cache_dir.canonicalize()?;
    std::env::set_var("SOS_CACHE", cache_dir);

    let exe = "target/debug/sos";
    let cmd = format!("{} account new mock-account-1", exe);
    let mut p = spawn(&cmd, Some(10000))?;
    p.exp_regex("memorize my master")?;
    p.send_line("y")?;
    p.exp_regex("create a new account")?;
    p.send_line("y")?;
    p.exp_eof()?;

    std::env::remove_var("SOS_PASSWORD");
    std::env::remove_var("SOS_CACHE");
    Ok(())
}
