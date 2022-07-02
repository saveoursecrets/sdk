use std::{
    borrow::Cow,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;
use uuid::Uuid;

use sos_client::{
    create_vault, exec, monitor, signup, Cache, ClientBuilder, Error, Result,
    run_blocking,
};
use sos_core::Algorithm;
use sos_readline::read_shell;
use terminal_banner::{Banner, Padding};

const WELCOME: &str = include_str!("welcome.txt");

/// Secret storage interactive shell.
#[derive(Parser, Debug)]
#[clap(name = "sos-client", author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create an account.
    Signup {
        /// Server URL.
        #[clap(short, long)]
        server: Url,

        /// Vault name.
        #[clap(short, long)]
        name: Option<String>,

        /// Directory to write the signing keystore.
        #[clap(parse(from_os_str))]
        keystore: PathBuf,
    },
    /// Launch the interactive shell.
    Shell {
        /// Server URL.
        #[clap(short, long)]
        server: Url,

        /// Keystore file containing the signing key.
        #[clap(short, long)]
        keystore: PathBuf,
    },
    /// Monitor server events.
    Monitor {
        /// Server URL.
        #[clap(short, long)]
        server: Url,

        /// Keystore file containing the signing key.
        #[clap(short, long)]
        keystore: PathBuf,
    },
    /// Create a new secret storage vault.
    ///
    /// A passphrase for the new vault will be read from
    /// stdin if data is detected on stdin otherwise a
    /// random diceware passphrase is generated and printed
    /// to the terminal.
    ///
    /// The filename will be the UUID for the new vault.
    Create {
        /// Unique identifier for the vault.
        #[clap(short, long)]
        uuid: Option<Uuid>,

        /// Public name for the vault.
        #[clap(short, long)]
        name: Option<String>,

        /// Encryption algorithm
        #[clap(short, long)]
        algorithm: Option<Algorithm>,

        /// Directory to write the vault file
        #[clap(parse(from_os_str))]
        destination: PathBuf,
    },
}

/// Ensure a supplied URL is https.
fn ensure_https(url: &Url) -> Result<()> {
    if url.scheme() != "https" {
        Err(Error::ServerHttps(url.clone()))
    } else {
        Ok(())
    }
}

/// Print the welcome information.
fn welcome(server: &Url) -> Result<()> {
    let help_info = r#"Type "help", "--help" or "-h" for command usage
Type "quit" or "q" to exit"#;
    let status_info = format!("Server: {}", server);
    let banner = Banner::new()
        .padding(Padding::one())
        .text(Cow::from(WELCOME))
        .text(Cow::from(help_info))
        .text(Cow::Owned(status_info))
        .render();
    println!("{}", banner);
    Ok(())
}

fn run() -> Result<()> {
    let args = Cli::parse();

    match args.cmd {
        Command::Monitor { server, keystore } => {
            ensure_https(&server)?;
            monitor(server, keystore)?;
        }
        Command::Create {
            destination,
            name,
            uuid,
            algorithm,
        } => {
            create_vault(destination, name, uuid, algorithm)?;
        }
        Command::Signup {
            server,
            keystore,
            name,
        } => {
            ensure_https(&server)?;
            signup(server, keystore, name)?;
        }
        Command::Shell { server, keystore } => {
            ensure_https(&server)?;
            let cache_dir = Cache::cache_dir()?;
            let client = ClientBuilder::new(server, keystore).build()?;
            let cache = Arc::new(RwLock::new(Cache::new(client, cache_dir)?));

            let reader = cache.read().unwrap();
            welcome(reader.client().server())?;
            drop(reader);

            let mut writer = cache.write().unwrap();
            if let Err(e) = run_blocking(writer.load_summaries()) {
                tracing::error!("failed to load vaults: {}", e);
            }
            drop(writer);

            let prompt_cache = Arc::clone(&cache);
            let prompt = || -> String {
                let cache = prompt_cache.read().unwrap();
                if let Some(current) = cache.current() {
                    return format!("sos@{}> ", current.name());
                }
                "sos> ".to_string()
            };

            read_shell(
                |line: String| {
                    let shell_cache = Arc::clone(&cache);
                    if let Err(e) = exec(&line, shell_cache) {
                        tracing::error!("{}", e);
                    }
                },
                prompt,
            )?;
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "sos_client=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();

    match run() {
        Ok(_) => {}
        Err(e) => {
            tracing::error!("{}", e);
        }
    }
    Ok(())
}
