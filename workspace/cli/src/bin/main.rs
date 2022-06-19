use anyhow::Result;
use clap::{Parser, Subcommand};
use sos_core::passphrase::WordCount;
use std::path::PathBuf;
use uuid::Uuid;

use sos_cli::{audit_log::*, vault::*, LOG_TARGET};
use sos_core::{secret::UuidOrName, Algorithm};

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
    /// Read audit logs.
    #[clap(subcommand)]
    Audit(Audit),
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

    /// Remove a secret from a vault
    #[clap(alias = "rm")]
    Remove {
        /// Vault file
        #[clap(parse(from_os_str))]
        vault: PathBuf,

        /// Secret name or uuid
        secret: UuidOrName,
    },

    #[clap(subcommand)]
    Add(VaultAdd),

    /// Display a secret in a vault
    Show {
        /// Vault file
        #[clap(parse(from_os_str))]
        vault: PathBuf,
        /// Secret name or uuid
        secret: UuidOrName,
    },
}

#[derive(Subcommand, Debug)]
enum VaultAdd {
    /// Create a new account
    Account {
        /// Label for the secret
        #[clap(short, long)]
        label: Option<String>,
        /// Vault file
        #[clap(parse(from_os_str))]
        vault: PathBuf,
    },
    /// Create a secret note
    Note {
        /// Label for the secret
        #[clap(short, long)]
        label: Option<String>,
        /// Vault file
        #[clap(parse(from_os_str))]
        vault: PathBuf,
    },
    /// Create a secret file
    File {
        /// Label for the secret
        #[clap(short, long)]
        label: Option<String>,
        /// Vault file
        #[clap(parse(from_os_str))]
        vault: PathBuf,
        /// Secret file
        #[clap(parse(from_os_str))]
        file: PathBuf,
    },
    /// Create a credentials list
    Credentials {
        /// Label for the secret
        #[clap(short, long)]
        label: Option<String>,
        /// Vault file
        #[clap(parse(from_os_str))]
        vault: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum Audit {
    /// Print the log records in an audit log
    #[clap(alias = "log")]
    Logs {
        /// Print each log record as a line of JSON
        #[clap(short, long)]
        json: bool,

        /// Audit log file
        #[clap(parse(from_os_str))]
        audit_log: PathBuf,
    },
}

fn run() -> Result<()> {
    let args = Cli::parse();
    match args.command {
        Command::New(cmd) => match cmd {
            New::Vault {
                destination,
                name,
                uuid,
                algorithm,
            } => {
                sos_cli::new::vault(destination, name, uuid, algorithm)?;
            }
            New::Keypair { name, destination } => {
                sos_cli::new::keypair(name, destination)?;
            }
            New::Jwt { name, destination } => {
                sos_cli::new::jwt(name, destination)?;
            }
            New::Passphrase { count } => {
                sos_cli::new::passphrase(count)?;
            }
        },
        /*
        Command::User(cmd) => match cmd {
            User::List { vault } => {
                sos_cli::user::list(vault)?;
            }
            User::Add { vault, public_key } => {
                sos_cli::user::add(vault, public_key)?;
            }
            User::Remove { vault, public_key } => {
                sos_cli::user::remove(vault, public_key)?;
            }
        },
        */
        Command::Vault(cmd) => match cmd {
            Vault::List { vault } => {
                list(vault)?;
            }
            Vault::Show { vault, secret } => {
                show(vault, secret)?;
            }
            Vault::Remove { vault, secret } => {
                remove(vault, secret)?;
            }
            Vault::Add(cmd) => match cmd {
                VaultAdd::Account { vault, label } => {
                    add_account(vault, label)?;
                }
                VaultAdd::Note { vault, label } => {
                    add_note(vault, label)?;
                }
                VaultAdd::File { vault, label, file } => {
                    add_file(vault, label, file)?;
                }
                VaultAdd::Credentials { vault, label } => {
                    add_credentials(vault, label)?;
                }
            },
        },
        Command::Audit(cmd) => match cmd {
            Audit::Logs { audit_log, json } => {
                print_audit_logs(audit_log, json)?;
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

    if let Err(e) = run() {
        log::error!(target: LOG_TARGET, "{}", e);
    }

    Ok(())
}
