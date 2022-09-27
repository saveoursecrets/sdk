use std::{
    borrow::Cow,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;

use sos_client::{
    exec, monitor, signup, Error, Result, ShellState, StdinPassphraseReader,
};
use sos_core::FileLocks;
use sos_readline::read_shell;
use terminal_banner::{Banner, Padding};

use sos_node::{
    cache_dir,
    client::{
        provider::{
            spawn_changes_listener, ProviderFactory,
        },
        run_blocking, SignerBuilder,
    },
};

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
            monitor(server, keystore)?;
        }
        Command::Signup {
            server,
            keystore,
            name,
        } => {
            signup(server, keystore, name)?;
        }
        Command::Shell { server, keystore } => {
            let server_url = server.clone();
            let cache_dir = cache_dir().ok_or_else(|| Error::NoCache)?;
            if !cache_dir.is_dir() {
                return Err(Error::NotDirectory(cache_dir));
            }

            let cache_lock = cache_dir.join("client.lock");
            let mut locks = FileLocks::new();
            let _ = locks.add(&cache_lock)?;

            let reader = StdinPassphraseReader {};
            let signer = SignerBuilder::new(keystore)
                .with_passphrase_reader(Box::new(reader))
                .with_use_agent(true)
                .build()?;

            let factory = ProviderFactory::Remote(server.clone());
            let (provider, address) = factory.create_provider(signer.clone())?;

            // Listen for change notifications
            spawn_changes_listener(server, signer, Arc::clone(&provider));

            // Prepare state for shell execution
            let shell_cache = Arc::clone(&provider);
            let state =
                Arc::new(RwLock::new(ShellState(shell_cache, address)));

            welcome(&server_url)?;

            // Authenticate and load initial vaults
            let mut writer = provider.write().unwrap();
            run_blocking(writer.authenticate())?;
            if let Err(e) = run_blocking(writer.load_vaults()) {
                tracing::error!("failed to list vaults: {}", e);
            }
            drop(writer);

            let prompt = || -> String {
                let cache = provider.read().unwrap();
                if let Some(current) = cache.current() {
                    return format!("sos@{}> ", current.name());
                }
                "sos> ".to_string()
            };

            read_shell(
                |line: String| {
                    let provider = Arc::clone(&state);
                    if let Err(e) = exec(&line, &server_url, provider) {
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
            std::env::var("RUST_LOG").unwrap_or_else(|_| {
                "sos_node::client=info,sos_client=info".into()
            }),
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
