use std::{
    borrow::Cow,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use parking_lot::RwLock as SyncRwLock;

use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;

use sos_client::{
    exec, local_signup, monitor, Error, Result, ShellState,
    StdinPassphraseReader,
};
use sos_core::{search::SearchIndex, FileLocks};
use sos_readline::read_shell;
use terminal_banner::{Banner, Padding};

use sos_node::{
    cache_dir,
    client::{
        account_manager::AccountManager,
        provider::{spawn_changes_listener, ProviderFactory},
        run_blocking, PassphraseReader,
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
    /// Create an account on this device.
    Signup {
        /// Name for the new identity.
        name: String,

        /// Name for the default folder.
        #[clap(short, long)]
        folder_name: Option<String>,
    },
    /// Launch the interactive shell.
    Shell {
        /// Provider factory.
        #[clap(short, long)]
        provider: Option<ProviderFactory>,

        /// Account name.
        account_name: String,
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
fn welcome(factory: &ProviderFactory) -> Result<()> {
    let help_info = r#"Type "help", "--help" or "-h" for command usage
Type "quit" or "q" to exit"#;
    let status_info = format!("Provider: {}", factory);
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
        Command::Signup { name, folder_name } => {
            local_signup(name, folder_name)?;
        }
        Command::Shell {
            provider,
            account_name,
        } => {
            let cache_dir = cache_dir().ok_or_else(|| Error::NoCache)?;
            if !cache_dir.is_dir() {
                return Err(Error::NotDirectory(cache_dir));
            }

            let cache_lock = cache_dir.join("client.lock");
            let mut locks = FileLocks::new();
            let _ = locks.add(&cache_lock)?;

            let accounts = AccountManager::list_accounts()?;

            let account = accounts
                .iter()
                .find(|a| a.label == account_name)
                .ok_or(Error::NoAccount(account_name.clone()))?;

            // Prepare a  search index for the identity vault
            let identity_index =
                Arc::new(SyncRwLock::new(SearchIndex::new(None)));

            let reader = StdinPassphraseReader {};
            let passphrase = reader.read()?;

            // Verify the identity vault can be unlocked
            let (account, user, keeper) = AccountManager::sign_in(
                &account.address,
                passphrase,
                Arc::clone(&identity_index),
            )?;

            let signer = user.signer;

            let factory = provider.unwrap_or_default();
            let (provider, address) =
                factory.create_provider(signer.clone())?;

            let provider = Arc::new(RwLock::new(provider));

            match &factory {
                ProviderFactory::Remote(remote) => {
                    // Listen for change notifications
                    spawn_changes_listener(
                        remote.clone(),
                        signer,
                        Arc::clone(&provider),
                    );
                }
                _ => {}
            }

            welcome(&factory)?;

            // Prepare state for shell execution
            let shell_cache = Arc::clone(&provider);
            let state = Arc::new(RwLock::new(ShellState(
                shell_cache,
                address,
                factory,
            )));

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
                    if let Err(e) = exec(&line, provider) {
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
