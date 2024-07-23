use super::{AuthenticatorUrls, OTP_AUTH_URLS};
use crate::{
    vault::{secret::Secret, Gatekeeper},
    Result,
};
use async_zip::{
    tokio::write::ZipFileWriter, Compression, ZipDateTimeBuilder,
    ZipEntryBuilder,
};
use std::{collections::HashMap, path::Path};
use time::OffsetDateTime;
use url::Url;

/// Export an authenticator vault to a zip archive.
///
/// The gatekeeper for the vault must be unlocked.
pub async fn export_authenticator(
    path: impl AsRef<Path>,
    source: &Gatekeeper,
    include_qr_codes: bool,
) -> Result<()> {
    // Gather TOTP secrets
    let mut totp_secrets = HashMap::new();
    for id in source.vault().keys() {
        if let Some((_, Secret::Totp { totp, .. }, _)) =
            source.read_secret(id).await?
        {
            totp_secrets.insert(*id, totp);
        }
    }

    let inner = tokio::fs::File::create(path.as_ref()).await?;
    let mut writer = ZipFileWriter::with_tokio(inner);

    // Write the JSON otpauth: URLs
    let mut auth_urls = AuthenticatorUrls::default();
    for (id, totp) in &totp_secrets {
        let url: Url = totp.get_url().parse()?;
        auth_urls.otp.insert(*id, url);
    }
    let buffer = serde_json::to_vec_pretty(&auth_urls)?;
    let entry = get_entry(OTP_AUTH_URLS)?;
    writer.write_entry_whole(entry, &buffer).await?;

    if include_qr_codes {
        for (id, totp) in totp_secrets {
            let name = format!("qr/{}.png", id);
            let buffer = totp.get_qr_png()?;
            let entry = get_entry(&name)?;
            writer.write_entry_whole(entry, &buffer).await?;
        }
    }

    writer.close().await?;
    Ok(())
}

fn get_entry(path: &str) -> Result<ZipEntryBuilder> {
    let now = OffsetDateTime::now_utc();
    let (hours, minutes, seconds) = now.time().as_hms();
    let month: u8 = now.month().into();

    let dt = ZipDateTimeBuilder::new()
        .year(now.year().into())
        .month(month.into())
        .day(now.day().into())
        .hour(hours.into())
        .minute(minutes.into())
        .second(seconds.into())
        .build();

    Ok(ZipEntryBuilder::new(path.into(), Compression::Deflate)
        .last_modification_date(dt))
}
