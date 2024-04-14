use clap::Subcommand;
use sos_net::sdk::{
    account::Account,
    crypto::{AccessKey, Cipher, KeyDerivation},
    identity::AccountRef,
};
use terminal_banner::{Banner, Padding};

use crate::{
    helpers::{
        account::resolve_user_with_password,
        messages::{info, success},
        readline::read_flag,
    },
    Result,
};

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Convert the cipher for an account.
    Cipher {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Key derivation function.
        #[clap(short, long)]
        kdf: Option<KeyDerivation>,

        /// Convert to this cipher.
        cipher: Cipher,
    },
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Cipher {
            account,
            cipher,
            kdf,
        } => {
            let (user, password) =
                resolve_user_with_password(account.as_ref(), false).await?;
            let mut owner = user.write().await;

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
                  "* Sync will overwrite data on servers".into());

            let result = banner.render();
            println!("{}", result);

            let prompt =
                format!(r#"Convert to cipher "{}" (y/n)? "#, &cipher);
            if read_flag(Some(&prompt))? {
                let access_key: AccessKey = password.into();
                let conversion =
                    owner.change_cipher(&access_key, &cipher, kdf.clone()).await?;
                if conversion.is_empty() {
                    info(format!(
                        "no files to convert, all folders use {} and {}",
                        cipher,
                        kdf.unwrap_or_default(),
                    ));
                } else {
                    success("cipher changed");
                }
            }
        }
    }
    Ok(())
}
