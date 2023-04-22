use std::{
    borrow::Cow,
    sync::{Arc, RwLock},
};

use clap::Subcommand;

use super::{exec, monitor, ShellState};
use sos_core::{storage::StorageDirs, url::Url};
use terminal_banner::{Banner, Padding};

use sos_node::{
    client::{
        provider::{spawn_changes_listener, ProviderFactory},
        run_blocking,
    },
    FileLocks,
};

use crate::helpers::account::{local_signup, sign_in};
use crate::helpers::readline::read_shell;
use crate::{Error, Result};

const WELCOME: &str = include_str!("welcome.txt");

#[derive(Subcommand, Debug)]
pub enum Command {
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

        /// Account name.
        #[clap(short, long)]
        account_name: String,
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

pub fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Monitor {
            server,
            account_name,
        } => {
            monitor(server, account_name)?;
        }
        Command::Signup { name, folder_name } => {
            local_signup(name, folder_name)?;
        }
        Command::Shell {
            provider,
            account_name,
        } => {
            let cache_dir =
                StorageDirs::cache_dir().ok_or_else(|| Error::NoCache)?;
            if !cache_dir.is_dir() {
                return Err(Error::NotDirectory(cache_dir));
            }

            let cache_lock = cache_dir.join("client.lock");
            let mut locks = FileLocks::new();
            locks.add(&cache_lock)?;

            let (info, user, identity_keeper, _device_signer, identity_index) =
                sign_in(&account_name)?;

            let factory = provider.unwrap_or_default();
            let (provider, address) =
                factory.create_provider(user.signer.clone())?;

            let provider = Arc::new(RwLock::new(provider));

            match &factory {
                ProviderFactory::Remote(remote) => {
                    // Listen for change notifications
                    spawn_changes_listener(
                        remote.clone(),
                        user.signer.clone(),
                        Arc::clone(&provider),
                    );
                }
                _ => {}
            }

            welcome(&factory)?;

            // Prepare state for shell execution
            let shell_cache = Arc::clone(&provider);
            let state = Arc::new(RwLock::new(ShellState {
                provider: shell_cache,
                address,
                factory,
                info,
                user,
                identity_keeper,
                identity_index,
            }));

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
