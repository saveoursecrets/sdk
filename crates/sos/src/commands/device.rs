use clap::Subcommand;
use std::sync::Arc;

use sos_net::sdk::{
    account::Account, device::TrustedDevice, identity::AccountRef,
};

use crate::{
    helpers::{
        account::{resolve_user, Owner},
        messages::success,
        readline::read_flag,
    },
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
    /// Revoke trust in a device.
    Revoke {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Device identifier.
        id: String,
    },
}

async fn resolve_device(
    user: Owner,
    id: &str,
) -> Result<Option<TrustedDevice>> {
    let owner = user.read().await;
    let owner = owner.selected_account().ok_or(Error::NoSelectedAccount)?;
    let devices = owner.trusted_devices().await?;
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
            let owner =
                owner.selected_account().ok_or(Error::NoSelectedAccount)?;
            let devices = owner.trusted_devices().await?;
            if verbose {
                println!("{}", serde_json::to_string_pretty(&devices)?);
            } else {
                for device in devices {
                    println!("{}", device.public_id()?);
                }
            }
        }
        Command::Revoke { account, id } => {
            let user = resolve_user(account.as_ref(), false).await?;
            if let Some(device) =
                resolve_device(Arc::clone(&user), &id).await?
            {
                let prompt = format!(r#"Revoke device "{}" (y/n)? "#, &id);
                if read_flag(Some(&prompt))? {
                    let mut owner = user.write().await;
                    let owner = owner
                        .selected_account_mut()
                        .ok_or(Error::NoSelectedAccount)?;
                    owner.revoke_device(device.public_key()).await?;
                    success("Device revoked");
                }
            } else {
                return Err(Error::DeviceNotFound(id));
            }
        }
    }
    Ok(())
}
