use anyhow::Result;
use serial_test::serial;
use std::{
    ops::DerefMut,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
};

use sos_sdk::{
    constants::DEFAULT_VAULT_NAME, passwd::diceware::generate_passphrase,
    secrecy::ExposeSecret, signer::ecdsa::Address, storage::StorageDirs,
    vault::VaultId,
};

use sos_net::migrate::import::ImportFormat;

use secrecy::SecretString;

use rexpect::{session::PtySession, spawn, ReadUntil};

type Session = Arc<Mutex<PtySession>>;

macro_rules! run {
    ($launch:ident, $cmd:ident, $spec:expr) => {{
        let ps = $launch(&$cmd)?;
        let is_shell = ps.is_some();
        let process = ps.unwrap_or_else(|| {
            Arc::new(Mutex::new(spawn(&$cmd, TIMEOUT).unwrap()))
        });
        let mut p = process.lock().expect("to acquire lock");
        $spec(p.deref_mut(), is_shell)?;
        if !is_shell {
            p.exp_eof()?;
        }
    }};
}

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

fn is_coverage() -> bool {
    env_is_set("COVERAGE") && env_is_set("COVERAGE_BINARIES")
}

fn is_ci() -> bool {
    env_is_set("CI")
}

fn env_is_set(name: &str) -> bool {
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

    account_new(&exe, &password, ACCOUNT_NAME)?;

    let address = account_list(&exe, ACCOUNT_NAME)?;
    let default_id = default_folder_id(&exe, &address, &password)?;

    check_vault(&exe, &address, &default_id, |_| Ok(None))?;
    //check_keys(&exe, &address, &default_id)?;
    //check_header(&exe, &address, &default_id)?;
    //check_log(&exe, &address, &default_id)?;

    //account_backup_restore(&exe, &address, &password)?;
    account_info(&exe, &address, &password, |_| Ok(None))?;
    //account_rename(&exe, &address, &password)?;
    //account_migrate(&exe, &address, &password)?;
    //account_contacts(&exe, &address, &password)?;

    /*
    folder_new(&exe, &address, &password)?;
    folder_list(&exe, &address, &password)?;
    folder_info(&exe, &address, &password)?;
    folder_keys(&exe, &address, &password)?;
    folder_commits(&exe, &address, &password)?;
    folder_rename(&exe, &address, &password)?;
    folder_history_compact(&exe, &address, &password)?;
    folder_history_check(&exe, &address, &password)?;
    folder_history_list(&exe, &address, &password)?;
    folder_remove(&exe, &address, &password)?;

    secret_add_note(&exe, &address, &password)?;
    secret_add_file(&exe, &address, &password)?;
    secret_add_login(&exe, &address, &password)?;
    secret_add_list(&exe, &address, &password)?;

    secret_list(&exe, &address, &password)?;
    secret_get(&exe, &address, &password)?;
    secret_info(&exe, &address, &password)?;
    secret_tags(&exe, &address, &password)?;
    secret_favorite(&exe, &address, &password)?;
    secret_rename(&exe, &address, &password)?;
    secret_move(&exe, &address, &password)?;
    secret_comment(&exe, &address, &password)?;
    secret_archive_unarchive(&exe, &address, &password)?;
    secret_download(&exe, &address, &password)?;

    // TODO: update

    secret_attach(&exe, &address, &password)?;
    secret_remove(&exe, &address, &password)?;

    account_delete(&exe, &address, &password)?;
    */

    StorageDirs::clear_cache_dir();
    std::env::remove_var("SOS_CACHE");
    std::env::remove_var("SOS_YES");
    std::env::remove_var("SOS_PASSWORD");
    Ok(())
}

/// Create a new account.
fn account_new(exe: &str, password: &SecretString, name: &str) -> Result<()> {
    let cmd = format!("{} account new {}", exe, name);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("2[)] Choose a password")?;
        p.send_line("2")?;
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
        p.exp_regex("Confirm password:")?;
        p.send_line(password.expose_secret())?;
        p.exp_regex("you want to create a new account")?;
        p.send_line("y")?;
    }
    p.exp_eof()?;

    Ok(())
}

/// Run a shell session.
fn shell(exe: &str, password: &SecretString) -> Result<()> {
    account_new(&exe, &password, SHELL_ACCOUNT_NAME)?;

    let address = account_list(&exe, SHELL_ACCOUNT_NAME)?;
    let default_id = default_folder_id(&exe, &address, &password)?;

    let cmd = format!("{} shell {}", exe, address);
    let mut ps = spawn(&cmd, TIMEOUT)?;
    let process = Arc::new(Mutex::new(ps));

    let prompt = format!("{}@{}>", SHELL_ACCOUNT_NAME, DEFAULT_VAULT_NAME);
    if !is_ci() {
        let mut p = process.lock().expect("process to lock");
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }

    {
        let mut p = process.lock().expect("process to lock");
        p.exp_regex(&prompt)?;
    }

    fn strip_exe(cmd: &str) -> String {
        let mut parts: Vec<_> = cmd.split(" ").collect();
        parts.remove(0);
        parts.join(" ")
    }

    fn wait_for_prompt<R>(
        runner: R,
        process: Session,
        prompt: &str,
    ) -> Result<()>
    where
        R: Fn() -> Result<()>,
    {
        runner()?;

        let mut p = process.lock().expect("process to lock");
        p.exp_regex(prompt)?;

        Ok(())
    }

    wait_for_prompt(
        || {
            check_vault(&exe, &address, &default_id, |cmd| {
                {
                    let mut p = process.lock().unwrap();
                    p.send_line(&strip_exe(cmd))?;
                }
                Ok(Some(Arc::clone(&process)))
            })
        },
        Arc::clone(&process),
        &prompt,
    )?;

    wait_for_prompt(
        || {
            account_info(&exe, &address, &password, |cmd| {
                {
                    let mut p = process.lock().unwrap();
                    p.send_line(&strip_exe(cmd))?;
                }
                Ok(Some(Arc::clone(&process)))
            })
        },
        Arc::clone(&process),
        &prompt,
    )?;

    {
        let mut p = process.lock().expect("process to lock");
        p.send_line("quit")?;
        p.exp_eof()?;
    }

    Ok(())
}

/// List accounts.
fn account_list(exe: &str, name: &str) -> Result<String> {
    let cmd = format!("{} account ls", exe);
    let mut p = spawn(&cmd, TIMEOUT)?;
    p.exp_string(name)?;
    p.exp_eof()?;

    let cmd = format!("{} account ls -v", exe);
    let mut p = spawn(&cmd, TIMEOUT)?;
    let result = p.read_line()?;
    p.exp_eof()?;

    let mut parts: Vec<&str> = result.split(' ').collect();
    let address: &str = parts.remove(0);
    let account_name: &str = parts.remove(0);

    assert!(address.parse::<Address>().is_ok());
    assert_eq!(name, account_name);
    Ok(address.to_owned())
}

/// Get the id of the default folder so we can
/// use it to execute the check subcommand which requires
/// paths to the files to check.
fn default_folder_id(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<VaultId> {
    let cmd =
        format!("{} folder info -a {} {}", exe, address, DEFAULT_VAULT_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
        p.read_line()?;
    }

    let result = p.read_line()?;
    p.exp_eof()?;

    Ok(result.parse()?)
}

fn check_vault<S>(
    exe: &str,
    address: &str,
    vault_id: &VaultId,
    launch: S,
) -> Result<()>
where
    S: Fn(&str) -> Result<Option<Session>>,
{
    let vault_path = StorageDirs::vault_path(address, vault_id.to_string())?;

    let cmd = format!("{} check vault {}", exe, vault_path.display());
    run!(launch, cmd, |p: &mut PtySession, is_shell: bool| -> Result<()> {
        p.exp_any(vec![ReadUntil::String(String::from("Verified"))])?;
        Ok(())
    });
    
    let cmd =
        format!("{} check vault --verbose {}", exe, vault_path.display());
    run!(launch, cmd, |p: &mut PtySession, is_shell: bool| -> Result<()> {
        p.exp_any(vec![ReadUntil::String(String::from("Verified"))])?;
        Ok(())
    });
    
    Ok(())
}

fn check_keys(exe: &str, address: &str, vault_id: &VaultId) -> Result<()> {
    let vault_path = StorageDirs::vault_path(address, vault_id.to_string())?;
    let cmd = format!("{} check keys {}", exe, vault_path.display());
    let mut p = spawn(&cmd, TIMEOUT)?;
    p.exp_any(vec![ReadUntil::EOF])?;
    Ok(())
}

fn check_header(exe: &str, address: &str, vault_id: &VaultId) -> Result<()> {
    let vault_path = StorageDirs::vault_path(address, vault_id.to_string())?;
    let cmd = format!("{} check header {}", exe, vault_path.display());
    let mut p = spawn(&cmd, TIMEOUT)?;
    p.exp_any(vec![ReadUntil::EOF])?;
    Ok(())
}

fn check_log(exe: &str, address: &str, vault_id: &VaultId) -> Result<()> {
    let log_path = StorageDirs::log_path(address, vault_id.to_string())?;

    let cmd = format!("{} check log {}", exe, log_path.display());
    let mut p = spawn(&cmd, TIMEOUT)?;
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!("{} check log --verbose {}", exe, log_path.display());
    let mut p = spawn(&cmd, TIMEOUT)?;
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

fn account_backup_restore(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cache_dir = StorageDirs::cache_dir().unwrap();
    let backup_file = cache_dir.join(format!("{}-backup.zip", address));

    let cmd = format!(
        "{} account backup -o {}",
        exe,
        backup_file.to_string_lossy()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    p.exp_regex("backup archive created")?;
    p.exp_eof()?;

    let cmd = format!(
        "{} account restore -i {}",
        exe,
        backup_file.to_string_lossy()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Overwrite all account")?;
        p.send_line("y")?;
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex(&format!("restored {}", ACCOUNT_NAME))?;
    p.exp_eof()?;

    Ok(())
}

fn account_info<S>(
    exe: &str,
    address: &str,
    password: &SecretString,
    launch: S,
) -> Result<()>
where
    S: Fn(&str) -> Result<Option<Session>>,
{

    let cmd = format!("{} account info -a {}", exe, address);
    run!(launch, cmd, |p: &mut PtySession, is_shell: bool| -> Result<()> {
        if !is_ci() && !is_shell {
            p.exp_regex("Password:")?;
            p.send_line(password.expose_secret())?;
        }
        Ok(())
    });
    
    let cmd = format!("{} account info -a {} -v", exe, address);
    run!(launch, cmd, |p: &mut PtySession, is_shell: bool| -> Result<()> {
        if !is_ci() && !is_shell {
            p.exp_regex("Password:")?;
            p.send_line(password.expose_secret())?;
        }
        Ok(())
    });
    
    let cmd = format!("{} account info -a {} --json", exe, address);
    run!(launch, cmd, |p: &mut PtySession, is_shell: bool| -> Result<()> {
        if !is_ci() && !is_shell {
            p.exp_regex("Password:")?;
            p.send_line(password.expose_secret())?;
        }
        Ok(())
    });
    
    Ok(())
}

fn account_rename(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cmd = format!(
        "{} account rename -a {} --name {}",
        exe, address, NEW_ACCOUNT_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("account renamed")?;
    p.exp_eof()?;

    let cmd = format!(
        "{} account rename -a {} --name {}",
        exe, address, ACCOUNT_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("account renamed")?;
    p.exp_eof()?;

    Ok(())
}

fn account_migrate(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cache_dir = StorageDirs::cache_dir().unwrap();
    let export_file = cache_dir.join(format!("{}-export.zip", address));
    let fixtures = PathBuf::from("workspace/migrate/fixtures");

    let cmd = format!(
        "{} account migrate -a {} export {}",
        exe,
        address,
        export_file.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
        p.exp_regex("Export UNENCRYPTED account")?;
        p.send_line("y")?;
    }
    p.exp_regex("account exported")?;
    p.exp_eof()?;

    let cmd = format!(
        "{} account migrate -a {} export --force {}",
        exe,
        address,
        export_file.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
        p.exp_regex("Export UNENCRYPTED account")?;
        p.send_line("y")?;
    }
    p.exp_regex("account exported")?;
    p.exp_eof()?;

    let file = fixtures.join("1password-export.csv");
    let cmd = format!(
        "{} account migrate -a {} import --format {} {}",
        exe,
        address,
        ImportFormat::OnePasswordCsv,
        file.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("file imported")?;
    p.exp_eof()?;

    let file = fixtures.join("dashlane-export.zip");
    let cmd = format!(
        "{} account migrate -a {} import --format {} {}",
        exe,
        address,
        ImportFormat::DashlaneZip,
        file.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("file imported")?;
    p.exp_eof()?;

    let file = fixtures.join("bitwarden-export.csv");
    let cmd = format!(
        "{} account migrate -a {} import --format {} {}",
        exe,
        address,
        ImportFormat::BitwardenCsv,
        file.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("file imported")?;
    p.exp_eof()?;

    let file = fixtures.join("chrome-export.csv");
    let cmd = format!(
        "{} account migrate -a {} import --format {} {}",
        exe,
        address,
        ImportFormat::ChromeCsv,
        file.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("file imported")?;
    p.exp_eof()?;

    let file = fixtures.join("firefox-export.csv");
    let cmd = format!(
        "{} account migrate -a {} import --format {} {}",
        exe,
        address,
        ImportFormat::FirefoxCsv,
        file.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("file imported")?;
    p.exp_eof()?;

    let file = fixtures.join("macos-export.csv");
    let cmd = format!(
        "{} account migrate -a {} import --format {} {}",
        exe,
        address,
        ImportFormat::MacosCsv,
        file.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("file imported")?;
    p.exp_eof()?;

    Ok(())
}

fn account_contacts(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let import_file = PathBuf::from("tests/fixtures/contacts.vcf");

    let cache_dir = StorageDirs::cache_dir().unwrap();
    let export_file = cache_dir.join(format!("{}-contacts.vcf", address));

    let cmd = format!(
        "{} account contacts -a {} import {}",
        exe,
        address,
        import_file.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("contacts imported")?;
    p.exp_eof()?;

    let cmd = format!(
        "{} account contacts -a {} export {}",
        exe,
        address,
        export_file.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("contacts exported")?;
    p.exp_eof()?;

    Ok(())
}

fn folder_new(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cmd = format!("{} folder new -a {} {}", exe, address, FOLDER_NAME);

    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("Folder created")?;
    p.exp_eof()?;

    Ok(())
}

fn folder_list(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cmd = format!("{} folder list -a {}", exe, address);

    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!("{} folder list --verbose -a {}", exe, address);

    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

fn folder_info(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cmd = format!("{} folder info -a {} {}", exe, address, FOLDER_NAME);

    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!(
        "{} folder info --verbose -a {} {}",
        exe, address, FOLDER_NAME
    );

    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

fn folder_keys(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cmd = format!("{} folder keys -a {} {}", exe, address, FOLDER_NAME);

    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

fn folder_commits(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cmd =
        format!("{} folder commits -a {} {}", exe, address, FOLDER_NAME);

    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

fn folder_rename(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cmd = format!(
        "{} folder rename -a {} -n {} {}",
        exe, address, NEW_FOLDER_NAME, FOLDER_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!(
        "{} folder rename -a {} -n {} {}",
        exe, address, FOLDER_NAME, NEW_FOLDER_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

fn folder_history_compact(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cmd = format!(
        "{} folder history compact -a {} {}",
        exe, address, FOLDER_NAME
    );

    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;

        p.exp_regex("Compaction will remove history")?;
        p.send_line("y")?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

fn folder_history_check(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cmd = format!(
        "{} folder history check -a {} {}",
        exe, address, FOLDER_NAME
    );

    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

fn folder_history_list(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cmd =
        format!("{} folder history list -a {} {}", exe, address, FOLDER_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!(
        "{} folder history list --verbose -a {} {}",
        exe, address, FOLDER_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

fn folder_remove(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cmd = format!("{} folder remove -a {} {}", exe, address, FOLDER_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;

        p.exp_regex("Delete folder")?;
        p.send_line("y")?;
    }
    p.exp_regex("Folder deleted")?;
    p.exp_eof()?;

    Ok(())
}

fn secret_add_note(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    if is_ci() {
        std::env::set_var("SOS_NOTE", NOTE_VALUE.to_string());
    }

    let cmd =
        format!("{} secret add note -a {} -n {}", exe, address, NOTE_NAME);

    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;

        p.exp_regex(">> ")?;
        p.send_line(NOTE_VALUE)?;
        p.exp_regex(">> ")?;
        p.send_control('d')?;
    }

    p.exp_regex("Secret created")?;
    p.exp_eof()?;

    if is_ci() {
        std::env::remove_var("SOS_NOTE");
    }

    Ok(())
}

fn secret_add_file(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let file = PathBuf::from("tests/fixtures/sample.heic").canonicalize()?;
    let cmd = format!(
        "{} secret add file -a {} -n {} {}",
        exe,
        address,
        FILE_NAME,
        file.display()
    );

    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }

    p.exp_regex("Secret created")?;
    p.exp_eof()?;

    Ok(())
}

fn secret_add_login(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let (account_password, _) = generate_passphrase()?;

    if is_ci() {
        std::env::set_var(
            "SOS_LOGIN_USERNAME",
            LOGIN_SERVICE_NAME.to_string(),
        );
        std::env::set_var("SOS_LOGIN_URL", LOGIN_URL.to_string());
        std::env::set_var(
            "SOS_LOGIN_PASSWORD",
            account_password.expose_secret().to_string(),
        );
    }

    let cmd =
        format!("{} secret add login -a {} -n {}", exe, address, LOGIN_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;

        p.exp_regex("Username:")?;
        p.send_line(LOGIN_SERVICE_NAME)?;

        p.exp_regex("Website:")?;
        p.send_line(LOGIN_URL)?;

        p.exp_regex("Password:")?;
        p.send_line(account_password.expose_secret())?;
    }

    p.exp_regex("Secret created")?;
    p.exp_eof()?;

    if is_ci() {
        std::env::remove_var("SOS_LOGIN_USERNAME");
        std::env::remove_var("SOS_LOGIN_URL");
        std::env::remove_var("SOS_LOGIN_PASSWORD");
    }

    Ok(())
}

fn secret_add_list(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let (value_1, _) = generate_passphrase()?;
    let (value_2, _) = generate_passphrase()?;

    if is_ci() {
        std::env::set_var(
            "SOS_LIST",
            format!(
                "{}={}\n{}={}\n",
                LIST_KEY_1,
                value_1.expose_secret(),
                LIST_KEY_2,
                value_2.expose_secret()
            ),
        );
    }

    let cmd =
        format!("{} secret add list -a {} -n {}", exe, address, LIST_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;

        p.exp_regex("Key:")?;
        p.send_line(LIST_KEY_1)?;

        p.exp_regex("Value:")?;
        p.send_line(value_1.expose_secret())?;

        p.exp_regex("Add more")?;
        p.send_line("y")?;

        p.exp_regex("Key:")?;
        p.send_line(LIST_KEY_2)?;

        p.exp_regex("Value:")?;
        p.send_line(value_2.expose_secret())?;

        p.exp_regex("Add more")?;
        p.send_line("n")?;
    }

    p.exp_regex("Secret created")?;
    p.exp_eof()?;

    if is_ci() {
        std::env::remove_var("SOS_LIST");
    }

    Ok(())
}

fn secret_list(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cmd = format!("{} secret list -a {}", exe, address);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!("{} secret list --verbose -a {}", exe, address);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!("{} secret list --all -a {}", exe, address);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!("{} secret list --favorites -a {}", exe, address);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

fn secret_get(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cmd = format!("{} secret get -a {} {}", exe, address, NOTE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!("{} secret get -a {} {}", exe, address, FILE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!("{} secret get -a {} {}", exe, address, LOGIN_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!("{} secret get -a {} {}", exe, address, LIST_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

fn secret_info(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cmd = format!("{} secret info -a {} {}", exe, address, NOTE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd =
        format!("{} secret info --debug -a {} {}", exe, address, NOTE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd =
        format!("{} secret info --json -a {} {}", exe, address, NOTE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

fn secret_tags(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let tags = "foo,bar,qux";

    let cmd = format!(
        "{} secret tags add -a {} --tags {} {}",
        exe, address, tags, NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd =
        format!("{} secret tags list -a {} {}", exe, address, NOTE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!(
        "{} secret tags rm -a {} --tags {} {}",
        exe, address, "foo,bar", NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd =
        format!("{} secret tags clear -a {} {}", exe, address, NOTE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

fn secret_favorite(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    // Add to favorites with first toggle
    let cmd = format!("{} secret favorite -a {} {}", exe, address, NOTE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    // Remove from favorites with second toggle
    let cmd = format!("{} secret favorite -a {} {}", exe, address, NOTE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

fn secret_rename(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cmd = format!(
        "{} secret rename -a {} --name {} {}",
        exe, address, NEW_NOTE_NAME, NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!(
        "{} secret rename -a {} --name {} {}",
        exe, address, NOTE_NAME, NEW_NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

fn secret_move(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let target_folder = "moved-secret-folder";

    // Create temporary folder
    let cmd = format!("{} folder new -a {} {}", exe, address, target_folder);

    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("Folder created")?;
    p.exp_eof()?;

    // Move to the new folder
    let cmd = format!(
        "{} secret move -a {} --target {} {}",
        exe, address, target_folder, NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("Secret moved")?;
    p.exp_eof()?;

    // Move back to the default folder
    let cmd = format!(
        "{} secret move -a {} --target {} --folder {} {}",
        exe, address, DEFAULT_VAULT_NAME, target_folder, NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("Secret moved")?;
    p.exp_eof()?;

    // Clean up the temporary folder
    let cmd =
        format!("{} folder remove -a {} {}", exe, address, target_folder);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;

        p.exp_regex("Delete folder")?;
        p.send_line("y")?;
    }
    p.exp_regex("Folder deleted")?;
    p.exp_eof()?;

    Ok(())
}

fn secret_comment(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    // Set a comment
    let cmd = format!(
        "{} secret comment -a {} --text {} {}",
        exe, address, "mock-comment", NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    // Clear the comment
    let cmd = format!(
        "{} secret comment -a {} --text '' {}",
        exe, address, NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

fn secret_archive_unarchive(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    // Move to archive
    let cmd = format!("{} secret archive -a {} {}", exe, address, NOTE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("Moved to archive")?;
    p.exp_eof()?;

    // Restore from archive
    let cmd =
        format!("{} secret unarchive -a {} {}", exe, address, NOTE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("Restored from archive")?;
    p.exp_eof()?;

    Ok(())
}

fn secret_download(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cache_dir = StorageDirs::cache_dir().unwrap();
    let output = cache_dir.join("sample.heic");

    let cmd = format!(
        "{} secret download -a {} {} {}",
        exe,
        address,
        FILE_NAME,
        output.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("Download complete")?;
    p.exp_eof()?;

    assert!(output.exists());

    Ok(())
}

fn secret_attach(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cache_dir = StorageDirs::cache_dir().unwrap();
    let input = PathBuf::from("tests/fixtures/sample.heic").canonicalize()?;
    let output = cache_dir.join("sample-attachment.heic");

    // Create file attachment
    let cmd = format!(
        "{} secret attach add file -a {} --name {} --path {} {}",
        exe,
        address,
        FILE_ATTACHMENT,
        input.display(),
        NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("Secret updated")?;
    p.exp_eof()?;

    // Create note attachment
    if is_ci() {
        std::env::set_var("SOS_NOTE", NOTE_VALUE.to_string());
    }
    let cmd = format!(
        "{} secret attach add note -a {} --name {} {}",
        exe, address, NOTE_ATTACHMENT, NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;

        p.exp_regex(">> ")?;
        p.send_line(NOTE_VALUE)?;
        p.exp_regex(">> ")?;
        p.send_control('d')?;
    }
    p.exp_regex("Secret updated")?;
    p.exp_eof()?;
    if is_ci() {
        std::env::remove_var("SOS_NOTE");
    }

    // Create link attachment
    if is_ci() {
        std::env::set_var("SOS_LINK", LINK_VALUE.to_string());
    }
    let cmd = format!(
        "{} secret attach add link -a {} --name {} {}",
        exe, address, LINK_ATTACHMENT, NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;

        p.exp_regex("URL:")?;
        p.send_line(LINK_VALUE)?;
    }
    p.exp_regex("Secret updated")?;
    p.exp_eof()?;
    if is_ci() {
        std::env::remove_var("SOS_LINK");
    }

    // Create password attachment
    let (attachment_password, _) = generate_passphrase()?;
    if is_ci() {
        std::env::set_var(
            "SOS_PASSWORD_VALUE",
            attachment_password.expose_secret().to_string(),
        );
    }
    let cmd = format!(
        "{} secret attach add password -a {} --name {} {}",
        exe, address, PASSWORD_ATTACHMENT, NOTE_NAME
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;

        p.exp_regex("Password:")?;
        p.send_line(attachment_password.expose_secret())?;
    }
    p.exp_regex("Secret updated")?;
    p.exp_eof()?;
    if is_ci() {
        std::env::remove_var("SOS_PASSWORD_VALUE");
    }

    // Get an attachment
    let cmd = format!(
        "{} secret attach get -a {} {} {}",
        exe, address, NOTE_NAME, NOTE_ATTACHMENT,
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    // List attachments
    let cmd =
        format!("{} secret attach ls -a {} {}", exe, address, NOTE_NAME,);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    let cmd = format!(
        "{} secret attach ls --verbose -a {} {}",
        exe, address, NOTE_NAME,
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    // Download file attachment
    let cmd = format!(
        "{} secret attach download -a {} {} {} {}",
        exe,
        address,
        NOTE_NAME,
        FILE_ATTACHMENT,
        output.display()
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_regex("Download complete")?;
    p.exp_eof()?;
    assert!(output.exists());

    // Remove an attachment
    let cmd = format!(
        "{} secret attach remove -a {} {} {}",
        exe, address, NOTE_NAME, NOTE_ATTACHMENT,
    );
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
    }
    p.exp_any(vec![ReadUntil::EOF])?;

    Ok(())
}

fn secret_remove(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cmd = format!("{} secret remove -a {} {}", exe, address, NOTE_NAME);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
        p.exp_regex("Delete secret")?;
        p.send_line("y")?;
    }
    p.exp_regex("Secret deleted")?;
    p.exp_eof()?;

    Ok(())
}

fn account_delete(
    exe: &str,
    address: &str,
    password: &SecretString,
) -> Result<()> {
    let cmd = format!("{} account delete -a {}", exe, address);
    let mut p = spawn(&cmd, TIMEOUT)?;
    if !is_ci() {
        p.exp_regex("Password:")?;
        p.send_line(password.expose_secret())?;
        p.exp_regex("Delete account")?;
        p.send_line("y")?;
    }
    p.exp_regex("account deleted")?;
    p.exp_eof()?;

    Ok(())
}
