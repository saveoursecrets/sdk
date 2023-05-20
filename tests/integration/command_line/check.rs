use anyhow::Result;
use std::{
    ops::DerefMut,
    sync::{Arc, Mutex},
};
use sos_sdk::{storage::StorageDirs, vault::VaultId};
use rexpect::{session::PtySession, spawn, ReadUntil};
use super::*;

pub fn vault(
    exe: &str,
    address: &str,
    vault_id: &VaultId,
    launch: Option<(Session, &str)>,
) -> Result<()> {
    let vault_path = StorageDirs::vault_path(address, vault_id.to_string())?;

    let cmd = format!("{} check vault {}", exe, vault_path.display());
    run!(launch, cmd, true, |ps: &mut PtySession,
                             _prompt: Option<&str>|
     -> Result<()> {
        ps.exp_any(vec![ReadUntil::String(String::from("Verified"))])?;
        Ok(())
    });

    let cmd =
        format!("{} check vault --verbose {}", exe, vault_path.display());
    run!(launch, cmd, true, |ps: &mut PtySession,
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
    launch: Option<(Session, &str)>,
) -> Result<()> {
    let vault_path = StorageDirs::vault_path(address, vault_id.to_string())?;
    let cmd = format!("{} check keys {}", exe, vault_path.display());
    run!(launch, cmd, false, |ps: &mut PtySession,
                              prompt: Option<&str>|
     -> Result<()> {
        if let Some(prompt) = prompt {
            wait_for_prompt(ps, prompt)?;
        } else {
            wait_for_eof(ps)?;
        }
        Ok(())
    });
    Ok(())
}

pub fn header(
    exe: &str,
    address: &str,
    vault_id: &VaultId,
    launch: Option<(Session, &str)>,
) -> Result<()> {
    let vault_path = StorageDirs::vault_path(address, vault_id.to_string())?;
    let cmd = format!("{} check header {}", exe, vault_path.display());
    run!(launch, cmd, false, |ps: &mut PtySession,
                              prompt: Option<&str>|
     -> Result<()> {
        if let Some(prompt) = prompt {
            wait_for_prompt(ps, prompt)?;
        } else {
            wait_for_eof(ps)?;
        }
        Ok(())
    });

    Ok(())
}

pub fn log(
    exe: &str,
    address: &str,
    vault_id: &VaultId,
    launch: Option<(Session, &str)>,
) -> Result<()> {
    let log_path = StorageDirs::log_path(address, vault_id.to_string())?;

    let cmd = format!("{} check log {}", exe, log_path.display());
    run!(launch, cmd, false, |ps: &mut PtySession,
                              prompt: Option<&str>|
     -> Result<()> {
        if let Some(prompt) = prompt {
            wait_for_prompt(ps, prompt)?;
        } else {
            wait_for_eof(ps)?;
        }
        Ok(())
    });

    let cmd = format!("{} check log --verbose {}", exe, log_path.display());
    run!(launch, cmd, false, |ps: &mut PtySession,
                              prompt: Option<&str>|
     -> Result<()> {
        if let Some(prompt) = prompt {
            wait_for_prompt(ps, prompt)?;
        } else {
            wait_for_eof(ps)?;
        }
        Ok(())
    });

    Ok(())
}
