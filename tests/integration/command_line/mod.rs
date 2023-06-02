use anyhow::Result;
use rexpect::{session::PtySession, spawn, ReadUntil};
use secrecy::SecretString;
use serial_test::serial;
use sos_sdk::{
    constants::{DEFAULT_ARCHIVE_VAULT_NAME, DEFAULT_VAULT_NAME},
    passwd::diceware::generate_passphrase,
    secrecy::ExposeSecret,
    storage::AppPaths,
    vfs,
};
use std::{
    ops::DerefMut,
    path::PathBuf,
    sync::{Arc, Mutex},
};

mod account;
mod check;
mod folder;
mod helpers;
mod secret;

type Session = Arc<Mutex<PtySession>>;

const TIMEOUT: Option<u64> = Some(30000);

const ACCOUNT_NAME: &str = "mock";
const SHELL_ACCOUNT_NAME: &str = "shell";

// Note we choose a name that sorts after all the
// other account names otherwise this account may
// appear first in the list as we parse the account
// address from the first in the list so if it sorts
// beforehand there be dragons.
const ALT_SHELL_ACCOUNT_NAME: &str = "zshell";

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
            if is_shell { "$ " } else { "" },
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
            std::thread::sleep(std::time::Duration::from_millis(10));
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

pub(crate) fn read_until_eof(
    cmd: String,
    password: Option<&SecretString>,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    run!(repl, cmd, false, |ps: &mut PtySession,
                            prompt: Option<&str>|
     -> Result<()> {
        if let Some(password) = password {
            if !is_ci() && prompt.is_none() {
                ps.exp_regex("Password:")?;
                ps.send_line(password.expose_secret())?;
            }
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

#[tokio::test]
#[serial]
async fn integration_command_line() -> Result<()> {
    let (password, _) = generate_passphrase()?;

    let cache_dir = PathBuf::from("target/command_line_test");
    let _ = vfs::remove_dir_all(&cache_dir).await;

    // Set cache directory for child processes
    std::env::set_var("SOS_CACHE", cache_dir.clone());
    // Set so test functions can access
    AppPaths::set_cache_dir(cache_dir);
    AppPaths::scaffold().await?;

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

    shell(&exe, &password).await?;

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
    account::statistics(&exe, &address, &password, None)?;
    account::rename(&exe, &address, &password, ACCOUNT_NAME, None)?;
    account::migrate(&exe, &address, &password, None)?;
    account::contacts(&exe, &address, &password, None)?;

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

    secret::add_note(&exe, &address, &password, None)?;
    secret::add_file(&exe, &address, &password, None)?;
    secret::add_login(&exe, &address, &password, None)?;
    secret::add_list(&exe, &address, &password, None)?;

    secret::list(&exe, &address, &password, None)?;
    secret::get(&exe, &address, &password, None)?;
    secret::cp(&exe, &address, &password, None)?;
    secret::info(&exe, &address, &password, None)?;
    secret::tags(&exe, &address, &password, None)?;
    secret::favorite(&exe, &address, &password, None)?;
    secret::rename(&exe, &address, &password, None)?;
    secret::mv(&exe, &address, &password, ACCOUNT_NAME, None)?;
    secret::comment(&exe, &address, &password, None)?;
    secret::archive_unarchive(&exe, &address, &password, None)?;
    secret::download(&exe, &address, &password, ACCOUNT_NAME, None).await?;

    // TODO: update

    secret::attach(&exe, &address, &password, ACCOUNT_NAME, None).await?;
    secret::remove(&exe, &address, &password, None)?;

    account::delete(&exe, &address, &password, None)?;

    AppPaths::clear_cache_dir();
    std::env::remove_var("SOS_CACHE");
    std::env::remove_var("SOS_YES");
    std::env::remove_var("SOS_PASSWORD");
    Ok(())
}

/// Login to a shell session.
fn login(
    exe: &str,
    address: &str,
    password: &SecretString,
    prompt: &str,
) -> Result<Session> {
    let cmd = format!("{} shell {}", exe, address);
    let ps = spawn(&cmd, TIMEOUT)?;
    let process = Arc::new(Mutex::new(ps));

    // Authenticate the user
    if !is_ci() {
        let mut p = process.lock().expect("to acquire lock");
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }

    // Wait for initial prompt
    {
        let mut p = process.lock().expect("to acquire lock");
        p.exp_regex(prompt)?;
    }

    Ok(process)
}

/// Run a shell session.
async fn shell(exe: &str, password: &SecretString) -> Result<()> {
    // Prepare variables for CI input
    helpers::set_note_ci_vars();
    let (account_password, _) = generate_passphrase()?;
    helpers::set_login_ci_vars(&account_password);
    let (value_1, _) = generate_passphrase()?;
    let (value_2, _) = generate_passphrase()?;
    helpers::set_list_ci_vars(&value_1, &value_2);

    helpers::set_link_ci_vars();
    let (attachment_password, _) = generate_passphrase()?;
    helpers::set_password_ci_vars(&attachment_password);

    account::new(&exe, &password, SHELL_ACCOUNT_NAME, None)?;
    let address = helpers::first_account_address(&exe, SHELL_ACCOUNT_NAME)?;
    let default_id = helpers::default_folder_id(&exe, &address, &password)?;

    let prompt = format_prompt(SHELL_ACCOUNT_NAME, DEFAULT_VAULT_NAME);
    let process = login(exe, &address, password, &prompt)?;

    // Login shell specific commands
    whoami(exe, &password, Some((Arc::clone(&process), &prompt)))?;
    pwd(exe, &password, Some((Arc::clone(&process), &prompt)))?;
    cd(exe, &password, Some((Arc::clone(&process), &prompt)))?;

    // Create alternative account so we can test the switch command
    account::new(&exe, &password, ALT_SHELL_ACCOUNT_NAME, None)?;
    switch(exe, &password, Some((Arc::clone(&process), &prompt)))?;

    // Check
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

    // Account
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
    account::statistics(
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
    account::contacts(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;

    // Folder
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

    // Secret
    secret::add_note(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    secret::add_file(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    secret::add_login(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    secret::add_list(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    secret::list(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    secret::get(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    secret::cp(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    secret::info(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    secret::tags(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    secret::favorite(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    secret::rename(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    secret::mv(
        &exe,
        &address,
        &password,
        SHELL_ACCOUNT_NAME,
        Some((Arc::clone(&process), &prompt)),
    )?;
    secret::comment(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    secret::archive_unarchive(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;
    secret::download(
        &exe,
        &address,
        &password,
        SHELL_ACCOUNT_NAME,
        Some((Arc::clone(&process), &prompt)),
    )
    .await?;

    // TODO: update

    secret::attach(
        &exe,
        &address,
        &password,
        SHELL_ACCOUNT_NAME,
        Some((Arc::clone(&process), &prompt)),
    )
    .await?;
    secret::remove(
        &exe,
        &address,
        &password,
        Some((Arc::clone(&process), &prompt)),
    )?;

    helpers::clear_note_ci_vars();
    helpers::clear_login_ci_vars();
    helpers::clear_list_ci_vars();
    helpers::clear_link_ci_vars();
    helpers::clear_password_ci_vars();

    // Quit the shell session
    {
        let mut p = process.lock().expect("to acquire lock");
        p.send_line("quit")?;
        p.exp_eof()?;
    }

    /* DELETE ACCOUNT */
    {
        let process = login(exe, &address, password, &prompt)?;
        account::delete(
            &exe,
            &address,
            &password,
            Some((Arc::clone(&process), &prompt)),
        )?;
    }

    Ok(())
}

fn whoami(
    exe: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let cmd = format!("{} whoami", exe);
    read_until_eof(cmd, Some(password), repl)
}

fn pwd(
    exe: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    let cmd = format!("{} pwd", exe);
    read_until_eof(cmd, Some(password), repl)
}

fn cd(
    exe: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    // Must update expected prompt
    let new_prompt =
        format_prompt(SHELL_ACCOUNT_NAME, DEFAULT_ARCHIVE_VAULT_NAME);
    let renamed = repl.clone().map(|(s, _p)| (s, &new_prompt[..]));

    let cmd = format!("{} cd {}", exe, DEFAULT_ARCHIVE_VAULT_NAME);
    read_until_eof(cmd, Some(password), renamed)?;

    let cmd = format!("{} cd {}", exe, DEFAULT_VAULT_NAME);
    read_until_eof(cmd, Some(password), repl)
}

fn switch(
    exe: &str,
    password: &SecretString,
    repl: Option<(Session, &str)>,
) -> Result<()> {
    // Must update expected prompt
    let new_prompt =
        format_prompt(ALT_SHELL_ACCOUNT_NAME, DEFAULT_VAULT_NAME);
    let renamed = repl.clone().map(|(s, _p)| (s, &new_prompt[..]));

    let cmd = format!("{} switch {}", exe, ALT_SHELL_ACCOUNT_NAME);
    run!(renamed, cmd, false, |ps: &mut PtySession,
                               prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
        }
        if let Some(prompt) = prompt {
            wait_for_prompt(ps, prompt)?;
        } else {
            wait_for_eof(ps)?;
        }
        Ok(())
    });

    let cmd = format!("{} switch {}", exe, SHELL_ACCOUNT_NAME);
    run!(repl, cmd, false, |ps: &mut PtySession,
                            prompt: Option<&str>|
     -> Result<()> {
        if !is_ci() {
            ps.exp_regex("Password:")?;
            ps.send_line(password.expose_secret())?;
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
