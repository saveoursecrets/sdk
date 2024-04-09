use clap::Subcommand;
use serde::{Deserialize, Serialize};
use sos_net::sdk::{
    account::{convert::ConvertCipher, Account},
    crypto::Cipher,
    identity::AccountRef,
};
use std::path::PathBuf;
use terminal_banner::{Banner, Padding};

use crate::{
    helpers::{account::resolve_user, messages::info, readline::read_flag},
    Error, Result,
};

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Convert the cipher for an account.
    Cipher {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Convert to this cipher.
        cipher: Cipher,
    },
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Cipher { account, cipher } => {
            let user = resolve_user(account.as_ref(), false).await?;
            let owner = user.read().await;

            let banner = Banner::new()
                .padding(Padding::one())
                .text("CONVERT CIPHER".into())
                .newline()
                .text(
                  "Changing a cipher is a risky operation, be sure you understand the risks.".into())
                .newline()
                .text(
                  "* Vault and event logs will be overwritten".into())
                .text(
                  "* Event history is compacted".into())
                .text(
                  "* Sync account with devices".into());

            let result = banner.render();
            println!("{}", result);

            let prompt =
                format!(r#"Convert to cipher "{}" (y/n)? "#, &cipher);
            if read_flag(Some(&prompt))? {
                let conversion =
                    ConvertCipher::build(&*owner, &cipher).await?;

                if conversion.identity.is_none()
                    && conversion.folders.is_empty()
                {
                    info(format!(
                        "no files to convert, all folders use {}",
                        cipher
                    ));
                } else {
                    let preview = toml::to_string_pretty(&conversion)?;
                    println!("{}", preview);
                }
            }
        }
    }
    Ok(())
}
