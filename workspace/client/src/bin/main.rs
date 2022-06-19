use std::{
    fs::File,
    io::Read,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use clap::{Parser, Subcommand};
use url::Url;
use web3_keystore::{decrypt, KeyStore};

use sos_client::{exec, list_vaults, signup, Client, Result, ShellState};
use sos_core::signer::SingleParty;
use sos_readline::{read_password, read_shell};

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
        Command::Signup {
            server,
            keystore,
            name,
        } => {
            signup(server, keystore, name)?;
        }
        Command::Shell { server, keystore } => {
            // Decrypt the keystore and create the client.
            let mut keystore_file = File::open(&keystore)?;
            let mut keystore_bytes = Vec::new();
            keystore_file.read_to_end(&mut keystore_bytes)?;
            let keystore: KeyStore = serde_json::from_slice(&keystore_bytes)?;

            let password = read_password(Some("Passphrase: "))?;
            let signing_bytes = decrypt(&keystore, &password)?;

            let signing_key: [u8; 32] = signing_bytes.as_slice().try_into()?;
            let signer: SingleParty = (&signing_key).try_into()?;
            let client = Arc::new(Client::new(server, Arc::new(signer)));

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
    match run() {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{}", e);
        }
    }
    Ok(())
}
