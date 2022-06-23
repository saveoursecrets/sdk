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
    create_vault, exec, list_vaults, monitor, signup, ClientBuilder, Result,
    ShellState,
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
                tracing::error!(
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
