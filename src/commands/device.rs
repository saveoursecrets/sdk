use clap::Subcommand;
use std::sync::Arc;
use tokio::sync::RwLock;

use sos_net::{
    client::NetworkAccount,
    sdk::{device::TrustedDevice, identity::AccountRef},
};

use crate::{
    helpers::{account::resolve_user, readline::read_flag},
    Error, Result,
};

#[derive(Subcommand, Debug)]
pub enum Command {
    /// List devices.
    #[clap(alias = "ls")]
    List {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Print more information.
        #[clap(short, long)]
        verbose: bool,
    },
    /// Remove a device.
    #[clap(alias = "rm")]
    Remove {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Device identifier.
        id: String,
    },
}

async fn resolve_device(
    user: Arc<RwLock<NetworkAccount>>,
    id: &str,
) -> Result<Option<TrustedDevice>> {
    let owner = user.read().await;
    let devices = owner.devices()?.list_trusted_devices();
    for device in devices {
        if device.public_id()? == id {
            return Ok(Some(device.clone()));
        }
    }
    Ok(None)
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::List { account, verbose } => {
            let user = resolve_user(account.as_ref(), false).await?;
            let owner = user.read().await;
            let devices = owner.devices()?.list_trusted_devices();
            for device in devices {
                println!("{}", device.public_id()?);
                if verbose {
                    print!("{}", device.extra_info());
                }
            }
        }
        Command::Remove { account, id } => {
            let user = resolve_user(account.as_ref(), false).await?;
            if let Some(device) =
                resolve_device(Arc::clone(&user), &id).await?
            {
                let prompt = format!(r#"Remove device "{}" (y/n)? "#, &id);
                if read_flag(Some(&prompt))? {
                    let mut owner = user.write().await;
                    owner.devices_mut()?.remove_device(&device).await?;
                    println!("Device removed ✓");
                }
            } else {
                return Err(Error::DeviceNotFound(id));
            }
        }
    }
    Ok(())
}
