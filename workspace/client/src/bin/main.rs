use std::{
    fs::File,
    io::Read,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use clap::{CommandFactory, Parser, Subcommand};
use std::future::Future;
use tokio::runtime::Runtime;
use url::Url;
use web3_keystore::{decrypt, KeyStore};

use sos_client::{Client, Result};
use sos_core::{secret::UuidOrName, signer::SingleParty, vault::Summary};
use sos_readline::{read_password, read_shell};

/// Secret storage interactive shell.
#[derive(Parser, Debug)]
#[clap(name = "sos-client", author, version, about, long_about = None)]
struct Cli {
    /// Server URL.
    #[clap(short, long)]
    server: Url,

    /// Keystore for the signing key.
    #[clap(short, long)]
    keystore: PathBuf,
}

/// Secret storage shell.
#[derive(Parser, Debug)]
#[clap(name = "sos-shell", author, version, about, long_about = None)]
struct Shell {
    #[clap(subcommand)]
    cmd: ShellCommand,
}

#[derive(Subcommand, Debug)]
enum ShellCommand {
    /// List vaults.
    #[clap(alias = "ls")]
    ListVaults {},
    /// Select a vault.
    Use { vault: UuidOrName },
    /// Clear selected vault.
    Clear,
    /// Exit the shell.
    #[clap(alias = "q")]
    Quit,
}

#[derive(Debug, Default)]
struct ShellState {
    /// Vaults managed by this signer.
    summaries: Vec<Summary>,
    /// Currently selected vault.
    current: Option<Summary>,
}

/// Runs a future blocking the current thread so we can
/// merge the synchronous nature of the shell prompt with the
/// asynchronous API exposed by the client.
fn run_blocking<F, R>(func: F) -> Result<R>
where
    F: Future<Output = Result<R>> + Send,
    R: Send,
{
    Ok(Runtime::new().unwrap().block_on(func)?)
}

fn print_summaries_list(summaries: &[Summary]) -> Result<()> {
    for (index, summary) in summaries.iter().enumerate() {
        println!("{}) {} {}", index + 1, summary.name(), summary.id());
    }
    Ok(())
}

fn run_shell_command(
    line: &str,
    client: Arc<Client>,
    state: Arc<RwLock<ShellState>>,
) -> Result<()> {
    let prefixed = format!("sos-shell {}", line);
    let it = prefixed.split_ascii_whitespace();
    let mut cmd = Shell::command();
    if line == "-V" {
        let version = cmd.render_version();
        print!("{}", version);
    } else if line == "version" || line == "--version" {
        let version = cmd.render_long_version();
        print!("{}", version);
    } else if line == "-h" {
        cmd.print_help()?;
    } else if line == "help" || line == "--help" {
        cmd.print_long_help()?;
    } else {
        match Shell::try_parse_from(it) {
            Ok(args) => match args.cmd {
                ShellCommand::ListVaults {} => {
                    let summaries = run_blocking(client.list_vaults())?;
                    print_summaries_list(&summaries)?;
                    let mut writer = state.write().unwrap();
                    writer.summaries = summaries;
                }
                ShellCommand::Use { vault } => {
                    let mut writer = state.write().unwrap();
                    let summary = match &vault {
                        UuidOrName::Name(name) => {
                            writer.summaries.iter().find(|s| s.name() == name)
                        }
                        UuidOrName::Uuid(uuid) => {
                            writer.summaries.iter().find(|s| s.id() == uuid)
                        }
                    };

                    if let Some(summary) = summary {
                        writer.current = Some(summary.clone());
                    } else {
                        eprintln!(
                            r#"vault "{}" not found, run "ls" to load the vault list"#,
                            vault
                        )
                    }
                }
                ShellCommand::Clear => {
                    let mut writer = state.write().unwrap();
                    writer.current = None;
                }
                ShellCommand::Quit => {
                    std::process::exit(0);
                }
            },
            Err(e) => e.print().expect("unable to write error output"),
        }
    }
    Ok(())
}

/// Print the welcome information.
fn welcome(api: &Url) -> Result<()> {
    println!("SOS: interactive shell");
    println!(r#"Type "help", "--help" or "-h" for command usage"#);
    println!(r#"Type "version", "--version" or "-V" for version info"#);
    println!(r#"Type "quit" or "q" to exit"#);
    println!("API: {}", api);
    Ok(())
}

fn run() -> Result<()> {
    let args = Cli::parse();

    // Decrypt the keystore and create the client.
    let mut keystore_file = File::open(&args.keystore)?;
    let mut keystore_bytes = Vec::new();
    keystore_file.read_to_end(&mut keystore_bytes)?;
    let keystore: KeyStore = serde_json::from_slice(&keystore_bytes)?;

    let password = read_password(Some("Passphrase: "))?;
    let signing_bytes = decrypt(&keystore, &password)?;

    let signing_key: [u8; 32] = signing_bytes.as_slice().try_into()?;
    let signer: SingleParty = (&signing_key).try_into()?;
    let client = Arc::new(Client::new(args.server, Arc::new(signer)));

    welcome(client.api())?;

    let state: Arc<RwLock<ShellState>> =
        Arc::new(RwLock::new(Default::default()));

    let prompt_state = Arc::clone(&state);

    let prompt = || -> String {
        let reader = prompt_state.read().unwrap();
        if let Some(current) = &reader.current {
            return format!("sos@{}> ", current.name());
        }
        "sos> ".to_string()
    };

    read_shell(
        |line: String| {
            let client = Arc::clone(&client);
            let state = Arc::clone(&state);
            run_shell_command(&line, client, state).unwrap();
        },
        prompt,
    )?;

    Ok(())
}

fn main() -> Result<()> {
    match run() {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{}", e);
        }
    }
    Ok(())
}
