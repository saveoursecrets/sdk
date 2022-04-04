use anyhow::Result;
use clap::{Parser, Subcommand};
use sos_core::passphrase::WordCount;
use std::path::PathBuf;
use uuid::Uuid;

use sos3_cli::LOG_TARGET;

/// Safe secret storage for the web3 era.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create vaults, keypairs and passphrases.
    #[clap(subcommand)]
    New(New),
    // Manage the authorized public keys for a vault.
    //#[clap(subcommand)]
    //User(User),
    /// Access a vault.
    #[clap(subcommand)]
    Vault(Vault),
}

#[derive(Subcommand, Debug)]
enum New {
    /// Create a new secret storage vault.
    ///
    /// A passphrase for the new vault will be read from
    /// stdin if data is detected on stdin otherwise a
    /// random diceware passphrase is generated and printed
    /// to the terminal.
    ///
    /// The filename will be the UUID for the new vault.
    Vault {
        #[clap(short, long)]
        uuid: Option<Uuid>,

        /// Directory to write the vault file
        #[clap(parse(from_os_str))]
        destination: PathBuf,
    },
    /// Create an ECDSA private and public key pair
    Keypair {
        /// Name for the private and public key files
        name: String,

        /// Directory to write the key files
        #[clap(parse(from_os_str))]
        destination: PathBuf,
    },
    /// Create an EdDSA private and public key pair for JWT
    Jwt {
        /// Name for the private and public key files
        name: String,

        /// Directory to write the keypair file
        #[clap(parse(from_os_str))]
        destination: PathBuf,
    },
    /// Print a random BIP39 passphrase
    Passphrase {
        /// Number of words: 12, 18 or 24.
        #[clap(short, long)]
        count: WordCount,
    },
}

/*
#[derive(Subcommand, Debug)]
enum User {
    /// List the public keys for a vault
    #[clap(alias = "ls")]
    List {
        /// Vault file
        #[clap(parse(from_os_str))]
        vault: PathBuf,
    },
    /// Add a public key to the vault
    Add {
        /// Vault file
        #[clap(parse(from_os_str))]
        vault: PathBuf,

        /// Public key file
        #[clap(parse(from_os_str))]
        public_key: PathBuf,
    },
    /// Remove a public key from the vault
    #[clap(alias = "rm")]
    Remove {
        /// Vault file
        #[clap(parse(from_os_str))]
        vault: PathBuf,

        /// Public key file
        #[clap(parse(from_os_str))]
        public_key: PathBuf,
    },
}
*/

#[derive(Subcommand, Debug)]
enum Vault {
    /// List the secrets in a vault
    #[clap(alias = "ls")]
    List {
        /// Vault file
        #[clap(parse(from_os_str))]
        vault: PathBuf,
    },

    #[clap(subcommand)]
    Add(VaultAdd),
}

#[derive(Subcommand, Debug)]
enum VaultAdd {
    /// Create a secret note
    #[clap(alias = "ls")]
    Note {
        #[clap(short, long)]
        label: String,

        /// Vault file
        #[clap(parse(from_os_str))]
        vault: PathBuf,
    },
}

fn run() -> Result<()> {
    let args = Cli::parse();
    match args.command {
        Command::New(cmd) => match cmd {
            New::Vault { destination, uuid } => {
                sos3_cli::new::vault(destination, uuid)?;
            }
            New::Keypair { name, destination } => {
                sos3_cli::new::keypair(name, destination)?;
            }
            New::Jwt { name, destination } => {
                sos3_cli::new::jwt(name, destination)?;
            }
            New::Passphrase { count } => {
                sos3_cli::new::passphrase(count)?;
            }
        },
        /*
        Command::User(cmd) => match cmd {
            User::List { vault } => {
                sos3_cli::user::list(vault)?;
            }
            User::Add { vault, public_key } => {
                sos3_cli::user::add(vault, public_key)?;
            }
            User::Remove { vault, public_key } => {
                sos3_cli::user::remove(vault, public_key)?;
            }
        },
        */
        Command::Vault(cmd) => match cmd {
            Vault::List { vault } => {
                sos3_cli::vault::list(vault)?;
            }
            Vault::Add(cmd) => match cmd {
                VaultAdd::Note { vault, label } => {
                    sos3_cli::vault::add_note(vault, label)?;
                }
            }
        },
    }
    Ok(())
}

fn main() -> Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    pretty_env_logger::init();

    match run() {
        Err(e) => {
            log::error!(target: LOG_TARGET, "{}", e);
        }
        _ => {}
    }

    Ok(())
}
