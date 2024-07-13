use crate::{
    migrate::Error,
    vault::{
        secret::{Secret, SecretMeta, SecretRow},
        Gatekeeper,
    },
    Result,
};
use async_zip::tokio::read::seek::ZipFileReader;
use std::path::Path;
use tokio::io::BufReader;
use totp_rs::TOTP;

use super::{AuthenticatorUrls, OTP_AUTH_URLS};

/// Import an authenticator vault from a zip archive.
pub async fn import_authenticator(
    path: impl AsRef<Path>,
    keeper: &mut Gatekeeper,
) -> Result<()> {
    let inner = BufReader::new(tokio::fs::File::open(path.as_ref()).await?);
    let mut reader = ZipFileReader::with_tokio(inner).await?;

    let mut urls: Option<AuthenticatorUrls> = None;

    for index in 0..reader.file().entries().len() {
        let entry = reader.file().entries().get(index).unwrap();
        let file_name = entry.filename();
        let file_name = file_name.as_str()?;
        if file_name == OTP_AUTH_URLS {
            let mut entry = reader.reader_with_entry(index).await?;

            let mut buffer = Vec::new();
            entry.read_to_end_checked(&mut buffer).await?;

            let auth_urls: AuthenticatorUrls =
                serde_json::from_slice(&buffer)?;

            urls = Some(auth_urls);
            break;
        }
    }

    let urls = urls.ok_or(Error::NoAuthenticatorUrls(
        path.as_ref().display().to_string(),
    ))?;

    for (id, url) in urls.otp {
        let totp = TOTP::from_url(url.to_string())?;
        let label = totp.account_name.clone();
        let secret = Secret::Totp {
            totp,
            user_data: Default::default(),
        };
        let meta = SecretMeta::new(label, secret.kind());
        let secret_data = SecretRow::new(id, meta, secret);
        keeper.create_secret(&secret_data).await?;
    }

    Ok(())
}
