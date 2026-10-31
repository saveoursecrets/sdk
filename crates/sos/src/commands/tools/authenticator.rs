use crate::{
    Error, Result,
    helpers::{
        account::resolve_user, messages::success, readline::read_flag,
    },
};
use clap::Subcommand;
use sos_account::{Account, FolderCreate};
use sos_client_storage::NewFolderOptions;
use sos_core::{AccountRef, VaultFlags};
use sos_migrate::{export_authenticator, import_authenticator};
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Export the TOTP secrets in an authenticator folder
    Export {
        /// Account name or address
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Include PNG images of the QR codes in the zip archive
        #[clap(short, long)]
        qr_codes: bool,

        /// Output zip archive
        file: PathBuf,
    },
    /// Import the TOTP secrets from a zip archive
    Import {
        /// Account name or address
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Name used when creating a new authenticator folder
        #[clap(short, long)]
        folder_name: Option<String>,

        /// Input zip archive
        file: PathBuf,
    },
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Export {
            account,
            file,
            qr_codes,
        } => {
            let user = resolve_user(account.as_ref(), false).await?;
            let owner = user.write().await;
            let owner =
                owner.selected_account().ok_or(Error::NoSelectedAccount)?;
            let authenticator = owner
                .authenticator_folder()
                .await
                .ok_or(Error::NoAuthenticatorFolder)?;

            let folder = owner.folder(authenticator.id()).await?;
            let access_point = folder.access_point();
            let access_point = access_point.lock().await;

            export_authenticator(file, &access_point, qr_codes).await?;
            success("authenticator TOTP secrets exported");
        }
        Command::Import {
            account,
            file,
            folder_name,
        } => {
            let user = resolve_user(account.as_ref(), false).await?;
            let mut owner = user.write().await;
            let owner = owner
                .selected_account_mut()
                .ok_or(Error::NoSelectedAccount)?;

            let folder = if let Some(authenticator) =
                owner.authenticator_folder().await
            {
                let prompt = format!(
                    r#"Overwrite secrets in the "{}" folder (y/n)? "#,
                    authenticator.name()
                );

                if read_flag(Some(&prompt))? {
                    Some(authenticator)
                } else {
                    None
                }
            } else {
                let options = NewFolderOptions {
                    name: folder_name.unwrap_or("Authenticator".to_string()),
                    flags: Some(
                        VaultFlags::AUTHENTICATOR
                            | VaultFlags::LOCAL
                            | VaultFlags::NO_SYNC,
                    ),
                    ..Default::default()
                };
                let FolderCreate { folder, .. } =
                    owner.create_folder(options).await?;
                Some(folder)
            };

            if let Some(folder) = folder {
                let folder = owner.folder(folder.id()).await?;
                let access_point = folder.access_point();
                let mut access_point = access_point.lock().await;

                import_authenticator(file, &mut access_point).await?;
                success("authenticator TOTP secrets imported");
            }
        }
    }
    Ok(())
}
