use anyhow::Result;
use serial_test::serial;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use sos_sdk::{
    constants::DEFAULT_VAULT_NAME, passwd::diceware::generate_passphrase,
    secrecy::ExposeSecret, storage::StorageDirs,
};
use secrecy::SecretString;
use rexpect::{session::PtySession, spawn, ReadUntil};

mod account;
mod check;
mod folder;
mod helpers;
mod secret;

type Session = Arc<Mutex<PtySession>>;

const TIMEOUT: Option<u64> = Some(30000);

const ACCOUNT_NAME: &str = "mock";
const SHELL_ACCOUNT_NAME: &str = "shell";

const NEW_ACCOUNT_NAME: &str = "mock-account-renamed";
const FOLDER_NAME: &str = "mock-folder";
const NEW_FOLDER_NAME: &str = "mock-folder-renamed";

const NOTE_NAME: &str = "mock-note";
const NOTE_VALUE: &str = "Mock note value\n";

const NEW_NOTE_NAME: &str = "mock-note-renamed";

const FILE_NAME: &str = "mock-file";

const LOGIN_NAME: &str = "mock-login";
const LOGIN_SERVICE_NAME: &str = "mock-service";
const LOGIN_URL: &str = "https://example.com";

const LIST_NAME: &str = "mock-list";
const LIST_KEY_1: &str = "SERVICE_1_API";
const LIST_KEY_2: &str = "SERVICE_2_API";

const FILE_ATTACHMENT: &str = "file-attachment";
const NOTE_ATTACHMENT: &str = "note-attachment";
const LINK_ATTACHMENT: &str = "link-attachment";
const PASSWORD_ATTACHMENT: &str = "password-attachment";
const LINK_VALUE: &str = "https://example.com";

// Run a test spec handling the differences between
// executing a process and entering a line in a shell session.
macro_rules! run {
    ($launch:ident, $cmd:ident, $eof:expr, $spec:expr) => {{
        // Get a PtySession which is either an existing session
        // in the case of the shell command otherwise we spawn
        // a new process/session
        let is_shell = $launch.is_some();

        println!(
            "{}{}",
            if is_shell { ">> " } else { "" },
            if is_shell {
                strip_exe(&$cmd)
            } else {
                $cmd.clone()
            }
        );

        let (process, prompt) = if let Some((session, prompt)) = &$launch {
            (Arc::clone(session), Some(prompt))
        } else {
            (Arc::new(Mutex::new(spawn(&$cmd, TIMEOUT).unwrap())), None)
        };

        let mut p = process.lock().expect("to acquire lock");

        // Run the shell command
        if is_shell {
            p.send_line(&strip_exe(&$cmd))?;
        }

        // Execute the test spec
        $spec(p.deref_mut(), prompt.copied())?;

        // Wait for the prompt (shell) or expect EOF
        if $eof {
            if let Some(prompt) = prompt {
                p.exp_regex(prompt)?;
            } else {
                p.exp_eof()?;
            }
        }

        if is_shell {
            // Leave a little time for data to flush otherwise
            // some tests will fail
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }};
}

pub(crate) use run;

pub(crate) fn format_prompt(account: &str, folder: &str) -> String {
    format!("{}@{}>", account, folder)
}

/// Strip executable name from a command, used when executing
/// in the context of a shell.
pub(crate) fn strip_exe(cmd: &str) -> String {
    let mut parts: Vec<_> = cmd.split(" ").collect();
    parts.remove(0);
    parts.join(" ")
}

pub(crate) fn wait_for_prompt(
    ps: &mut PtySession,
    prompt: &str,
) -> Result<()> {
    ps.exp_any(vec![ReadUntil::String(prompt.to_string())])?;
    Ok(())
}

pub(crate) fn wait_for_eof(ps: &mut PtySession) -> Result<()> {
    ps.exp_any(vec![ReadUntil::EOF])?;
    Ok(())
}

pub(crate) fn is_coverage() -> bool {
    env_is_set("COVERAGE") && env_is_set("COVERAGE_BINARIES")
}

pub(crate) fn is_ci() -> bool {
    env_is_set("CI")
}

pub(crate) fn env_is_set(name: &str) -> bool {
    std::env::var(name).is_ok() && !std::env::var(name).unwrap().is_empty()
}

#[test]
#[serial]
fn integration_command_line() -> Result<()> {
    let (password, _) = generate_passphrase()?;

    let cache_dir = PathBuf::from("target/command_line_test");
    if cache_dir.exists() {
        std::fs::remove_dir_all(&cache_dir)?;
    }
    std::fs::create_dir_all(&cache_dir)?;

    let cache_dir = cache_dir.canonicalize()?;
    // Set cache directory for child processes
    std::env::set_var("SOS_CACHE", cache_dir.clone());
    // Set so test functions can access
    StorageDirs::set_cache_dir(cache_dir);

    if is_ci() {
        std::env::set_var("SOS_YES", true.to_string());
        std::env::set_var("SOS_PASSWORD", password.expose_secret());
    }

    let exe = if is_coverage() {
        PathBuf::from(std::env::var("COVERAGE_BINARIES")?)
            .join("sos")
            .to_string_lossy()
            .into_owned()
    } else {
        "target/debug/sos".to_owned()
    };

    shell(&exe, &password)?;

    account::new(&exe, &password, ACCOUNT_NAME, None)?;

    let address = helpers::first_account_address(&exe, ACCOUNT_NAME)?;
    let default_id = helpers::default_folder_id(&exe, &address, &password)?;

    check::vault(&exe, &address, &default_id, None)?;
    check::keys(&exe, &address, &default_id, None)?;
    check::header(&exe, &address, &default_id, None)?;
    check::log(&exe, &address, &default_id, None)?;

    account::list(&exe, ACCOUNT_NAME, None)?;
    account::backup_restore(&exe, &address, &password, ACCOUNT_NAME, None)?;
    account::info(&exe, &address, &password, None)?;
    account::rename(&exe, &address, &password, ACCOUNT_NAME, None)?;
    account::migrate(&exe, &address, &password, None)?;
    //account::contacts(&exe, &address, &password)?;

    folder::new(&exe, &address, &password, None)?;
    folder::list(&exe, &address, &password, None)?;
    folder::info(&exe, &address, &password, None)?;
    folder::keys(&exe, &address, &password, None)?;
    folder::commits(&exe, &address, &password, None)?;
    folder::rename(&exe, &address, &password, None)?;
    folder::history_compact(&exe, &address, &password, None)?;
    folder::history_check(&exe, &address, &password, None)?;
    folder::history_list(&exe, &address, &password, None)?;
    folder::remove(&exe, &address, &password, None)?;

    secret::add_note(&exe, &address, &password)?;
    secret::add_file(&exe, &address, &password)?;
    secret::add_login(&exe, &address, &password)?;
    secret::add_list(&exe, &address, &password)?;

    secret::list(&exe, &address, &password)?;
    secret::get(&exe, &address, &password)?;
    secret::info(&exe, &address, &password)?;
    secret::tags(&exe, &address, &password)?;
    secret::favorite(&exe, &address, &password)?;
    secret::rename(&exe, &address, &password)?;
    secret::mv(&exe, &address, &password)?;
    secret::comment(&exe, &address, &password)?;
    secret::archive_unarchive(&exe, &address, &password)?;
    secret::download(&exe, &address, &password)?;

    // TODO: update

    secret::attach(&exe, &address, &password)?;
    secret::remove(&exe, &address, &password)?;

    account::delete(&exe, &address, &password, None)?;

    StorageDirs::clear_cache_dir();
    std::env::remove_var("SOS_CACHE");
    std::env::remove_var("SOS_YES");
    std::env::remove_var("SOS_PASSWORD");
    Ok(())
}

/// Run a shell session.
fn shell(exe: &str, password: &SecretString) -> Result<()> {
    account::new(&exe, &password, SHELL_ACCOUNT_NAME, None)?;

    let address = helpers::first_account_address(&exe, SHELL_ACCOUNT_NAME)?;
    let default_id = helpers::default_folder_id(&exe, &address, &password)?;

    let cmd = format!("{} shell {}", exe, address);
    let ps = spawn(&cmd, TIMEOUT)?;
    let process = Arc::new(Mutex::new(ps));

    let prompt = format_prompt(SHELL_ACCOUNT_NAME, DEFAULT_VAULT_NAME);

    // Authenticate the user
    if !is_ci() {
        let mut p = process.lock().expect("process to lock");
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }

    // Wait for initial prompt
    {
        let mut p = process.lock().expect("process to lock");
        p.exp_regex(&prompt)?;
    }

    // TODO: cd
    // TODO: whoami

    // Issue commands

    /* CHECK */
    check::vault(
        &exe,
        &address,
        &default_id,
        Some((Arc::clone(&process), &prompt)),
    )?;
    check::keys(
        &exe,
        &address,
        &default_id,
        Some((Arc::clone(&process), &prompt)),
    )?;
    check::header(
        &exe,
        &address,
        &default_id,
        Some((Arc::clone(&process), &prompt)),
    )?;
    check::log(
        &exe,
        &address,
        &default_id,
        Some((Arc::clone(&process), &prompt)),
    )?;

    /* ACCOUNT */
    account::list(
        &exe,
        SHELL_ACCOUNT_NAME,
        Some((Arc::clone(&process), &prompt)),
    )?;
    account::backup_restore(
        &exe,
        &address,
        &password,
        SHELL_ACCOUNT_NAME,
        Some((Arc::clone(&process), &prompt)),
    )?;
    account::info(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    account::rename(
        &exe,
        &address,
        &password,
        SHELL_ACCOUNT_NAME,
        Some((Arc::clone(&process), &prompt)),
    )?;
    account::migrate(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;

    folder::new(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    folder::list(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    folder::info(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    folder::keys(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    folder::commits(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    folder::rename(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    folder::history_compact(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    folder::history_check(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    folder::history_list(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    folder::remove(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;

    /* DELETE ACCOUNT */
    account::delete(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;

    /*
    // Quit the shell session
    {
        let mut p = process.lock().expect("process to lock");
        p.send_line("quit")?;
        p.exp_eof()?;
    }
    */

    Ok(())
}
