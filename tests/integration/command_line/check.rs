use super::*;
use anyhow::Result;
use rexpect::{session::PtySession, spawn, ReadUntil};
use sos_net::sdk::{storage::AppPaths, vault::VaultId};
use std::{
    ops::DerefMut,
    sync::{Arc, Mutex},
};

pub fn vault(
    exe: &str,
    address: &str,
    vault_id: &VaultId,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let vault_path = AppPaths::vault_path(address, vault_id.to_string())?;

    let cmd = format!("{} check vault {}", exe, vault_path.display());
    run!(repl, cmd, true, |ps: &mut PtySession,
                           _prompt: Option<&str>|
     -> Result<()> {
        ps.exp_any(vec![ReadUntil::String(String::from("Verified"))])?;
        Ok(())
    });

    let cmd =
        format!("{} check vault --verbose {}", exe, vault_path.display());
    run!(repl, cmd, true, |ps: &mut PtySession,
                           _prompt: Option<&str>|
     -> Result<()> {
        ps.exp_any(vec![ReadUntil::String(String::from("Verified"))])?;
        Ok(())
    });

    Ok(())
}

pub fn keys(
    exe: &str,
    address: &str,
    vault_id: &VaultId,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let vault_path = AppPaths::vault_path(address, vault_id.to_string())?;
    let cmd = format!("{} check keys {}", exe, vault_path.display());
    read_until_eof(cmd, None, repl)
}

pub fn header(
    exe: &str,
    address: &str,
    vault_id: &VaultId,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let vault_path = AppPaths::vault_path(address, vault_id.to_string())?;
    let cmd = format!("{} check header {}", exe, vault_path.display());
    read_until_eof(cmd, None, repl)
}

pub fn log(
    exe: &str,
    address: &str,
    vault_id: &VaultId,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let log_path = AppPaths::event_log_path(address, vault_id.to_string())?;

    let cmd = format!("{} check log {}", exe, log_path.display());
    read_until_eof(cmd, None, repl.clone())?;

    let cmd = format!("{} check log --verbose {}", exe, log_path.display());
    read_until_eof(cmd, None, repl)
}
