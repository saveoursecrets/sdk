use std::{fs::File, io::Read, path::PathBuf, sync::Arc, thread::spawn};

use clap::{CommandFactory, Parser, Subcommand};
use std::future::Future;
use tokio::runtime::Runtime;
use url::Url;
use web3_keystore::{decrypt, KeyStore};
use once_cell::sync::OnceCell;

use sos_client::{Client, Result};
use sos_core::signer::SingleParty;
use sos_readline::{read_password, read_shell};

/// Secret storage interactive shell.
#[derive(Parser, Debug)]
#[clap(name = "sos-client", author, version, about, long_about = None)]
struct Cli {
    /// Server API URL.
    #[clap(short, long)]
    api: Url,

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
    ListVaults {},
}

/// Hack to give the client a 'static lifetime which is required
/// to pass the futures created into the spawned thread used to block
/// the shell prompt.
fn global_client(value: Option<(Url, SingleParty)>) -> &'static Arc<Client> {
    static INSTANCE: OnceCell<Arc<Client>> = OnceCell::new();
    INSTANCE.get_or_init(|| {
        let value = value.unwrap();
        Arc::new(Client::new(value.0, Arc::new(value.1)))
    })
}

/// Runs a future in a separate thread and runtime so we can
/// merge the synchronous nature of the shell prompt with the
/// asynchronous API exposed by the client.
fn run_blocking<F, R>(func: F) -> Result<R>
where
    F: Future<Output = Result<R>> + Send + Sync + 'static,
    R: Send + Sync + 'static
{
    let handle = spawn(move || {
        Runtime::new().unwrap().block_on(func)
    });

    let result = handle.join().unwrap();
    let inner = result?;
    return Ok(inner);
}

fn run_shell_command(line: &str) -> Result<()> {
    let client = global_client(None);
    let prefixed = format!("sos-shell {}", line);
    let it = prefixed.split_ascii_whitespace();
    let mut cmd = Shell::command();
    if line == "quit" || line == "q" {
        std::process::exit(0);
    } else if line == "-V" {
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
            Ok(args) => {
                println!("Run shell command {:#?}", args);
                match args.cmd {
                    ShellCommand::ListVaults {} => {
                        let summaries = run_blocking(client.login())?;
                        println!("summaries {:#?}", summaries);
                    }
                }
            }
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

async fn run() -> Result<()> {
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
    let client = global_client(Some((args.api, signer)));

    welcome(client.api())?;

    read_shell(
        |line: String| {
            run_shell_command(&line).unwrap();
        },
        Some("sos> "),
    )?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    match run().await {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{}", e);
        }
    }
    Ok(())
}
