use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;

use sos_client::{
    exec, list_vaults, monitor, signup, ClientBuilder, Result, ShellState,
};
use sos_readline::read_shell;

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
    println!("{}", WELCOME.trim());
    println!("# Server {}", server);
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
            let client =
                Arc::new(ClientBuilder::new(server, keystore).build()?);

            welcome(client.server())?;

            let state: Arc<RwLock<ShellState>> =
                Arc::new(RwLock::new(Default::default()));

            if let Err(e) =
                list_vaults(Arc::clone(&client), Arc::clone(&state), false)
            {
                eprintln!(
                    "failed to list vaults, identity may not exist: {}",
                    e
                );
            }

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
                    if let Err(e) = exec(&line, client, state) {
                        eprintln!("{}", e);
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
        .with(tracing_subscriber::fmt::layer())
        .init();

    match run() {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{}", e);
        }
    }
    Ok(())
}
