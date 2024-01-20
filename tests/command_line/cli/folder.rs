use super::*;
use anyhow::Result;
use rexpect::{session::PtySession, spawn};
use secrecy::SecretString;
use sos_net::sdk::secrecy::ExposeSecret;
use std::{
    ops::DerefMut,
    sync::{Arc, Mutex},
};

pub fn new(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let cmd = format!("{} folder new -a {} {}", exe, address, FOLDER_NAME);
    run!(repl, cmd, true, |ps: &mut PtySession,
                           prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() && prompt.is_none() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }
        ps.exp_regex("Folder created")?;
        Ok(())
    });

    Ok(())
}

pub fn list(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let cmd = format!("{} folder list -a {}", exe, address);
    read_until_eof(cmd, Some(password), repl.clone())?;

    let cmd = format!("{} folder list --verbose -a {}", exe, address);
    read_until_eof(cmd, Some(password), repl)
}

pub fn info(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let cmd = format!("{} folder info -a {} {}", exe, address, FOLDER_NAME);
    read_until_eof(cmd, Some(password), repl.clone())?;

    let cmd = format!(
        "{} folder info --verbose -a {} {}",
        exe, address, FOLDER_NAME
    );
    read_until_eof(cmd, Some(password), repl)
}

pub fn keys(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let cmd = format!("{} folder keys -a {} {}", exe, address, FOLDER_NAME);
    read_until_eof(cmd, Some(password), repl)
}

pub fn commits(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let cmd =
        format!("{} folder commits -a {} {}", exe, address, FOLDER_NAME);
    read_until_eof(cmd, Some(password), repl)
}

pub fn rename(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let cmd = format!(
        "{} folder rename -a {} -n {} {}",
        exe, address, NEW_FOLDER_NAME, FOLDER_NAME
    );
    read_until_eof(cmd, Some(password), repl.clone())?;

    let cmd = format!(
        "{} folder rename -a {} -n {} {}",
        exe, address, FOLDER_NAME, NEW_FOLDER_NAME
    );
    read_until_eof(cmd, Some(password), repl)
}

pub fn history_compact(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let cmd = format!(
        "{} folder history compact -a {} {}",
        exe, address, FOLDER_NAME
    );
    run!(repl, cmd, false, |ps: &mut PtySession,
                            prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() && prompt.is_none() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }

        if !is_ci() {
            ps.exp_regex("Compaction will remove history")?;
            ps.send_line("y")?;
        }

        if let Some(prompt) = prompt {
            wait_for_prompt(ps, prompt)?;
        } else {
            wait_for_eof(ps)?;
        }
        Ok(())
    });

    Ok(())
}

pub fn history_check(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let cmd = format!(
        "{} folder history check -a {} {}",
        exe, address, FOLDER_NAME
    );
    read_until_eof(cmd, Some(password), repl)
}

pub fn history_list(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let cmd =
        format!("{} folder history list -a {} {}", exe, address, FOLDER_NAME);
    read_until_eof(cmd, Some(password), repl.clone())?;

    let cmd = format!(
        "{} folder history list --verbose -a {} {}",
        exe, address, FOLDER_NAME
    );
    read_until_eof(cmd, Some(password), repl)
}

pub fn remove(
    exe: &str,
    address: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let cmd = format!("{} folder remove -a {} {}", exe, address, FOLDER_NAME);
    run!(repl, cmd, true, |ps: &mut PtySession,
                           prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() && prompt.is_none() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }
        if !is_ci() {
            ps.exp_regex("Delete folder")?;
            ps.send_line("y")?;
        }
        ps.exp_regex("Folder deleted")?;
        Ok(())
    });

    Ok(())
}
