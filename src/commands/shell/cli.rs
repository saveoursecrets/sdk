use std::{borrow::Cow, sync::Arc};

use super::exec;
use sos_core::{account::AccountRef, storage::StorageDirs};
use terminal_banner::{Banner, Padding};

use sos_node::{
    client::{provider::ProviderFactory, UserStorage},
    peer::convert_libp2p_identity,
    FileLocks,
};

use tokio::sync::RwLock;

use crate::{
    helpers::{
        account::{sign_in, USER},
        readline,
    },
    Error, Result,
};

const WELCOME: &str = include_str!("welcome.txt");

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

pub async fn run(
    provider: Option<ProviderFactory>,
    account: AccountRef,
) -> Result<()> {
    let cache_dir = StorageDirs::cache_dir().ok_or_else(|| Error::NoCache)?;
    if !cache_dir.is_dir() {
        return Err(Error::NotDirectory(cache_dir));
    }

    let cache_lock = cache_dir.join("client.lock");
    let mut locks = FileLocks::new();
    locks.add(&cache_lock)?;

    let (user, _) = sign_in(&account)?;

    let factory = provider.unwrap_or_default();
    let (mut storage, _) =
        factory.create_provider(user.identity().signer().clone())?;
    welcome(&factory)?;

    // Authenticate and load initial vaults
    storage.authenticate().await?;
    storage.load_vaults().await?;

    // FIXME: support ephemeral device signer for when the CLI
    // FIXME: is running on the same device as a GUI
    let peer_key = convert_libp2p_identity(user.device().signer())?;

    let owner = UserStorage {
        user,
        storage,
        peer_key,
        factory,
    };

    /*
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
    */

    // Prepare state for shell execution
    let state = USER.get_or_init(|| Arc::new(RwLock::new(owner)));

    let mut rl = readline::basic_editor()?;
    loop {
        let prompt_value = {
            let owner = state.read().await;
            if let Some(current) = owner.storage.current() {
                format!("sos@{}> ", current.name())
            } else {
                "sos> ".to_string()
            }
        };
        let readline = rl.readline(&prompt_value);
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str())?;
                let provider = Arc::clone(&state);
                if let Err(e) = exec(&line, provider).await {
                    tracing::error!("{}", e);
                }
            }
            Err(e) => return Err(Error::Readline(e)),
        }
    }
}
