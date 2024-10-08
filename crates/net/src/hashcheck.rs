//! Check password hashes using the hashcheck service.
use super::{is_offline, Result};
use tracing::instrument;

/// Default endpoint for HIBP database checks.
const ENDPOINT: &str = "https://hashcheck.saveoursecrets.com";

/// Check a single SHA1 hash of a password exists in the HIBP
/// database by calling an endpoint.
#[instrument(skip_all)]
pub async fn single(
    password_hash: String,
    host: Option<String>,
) -> Result<bool> {
    if is_offline() {
        tracing::warn!("offline mode active, ignoring hashcheck");
        return Ok(false);
    }

    let host = host.unwrap_or_else(|| ENDPOINT.to_owned());
    tracing::info!(host = %host, "hashcheck");
    let url = format!("{}/{}", host, password_hash.to_uppercase());
    let client = reqwest::Client::new();
    let res = client.get(url).send().await?;
    tracing::debug!(status = %res.status(), "hashcheck");
    let res = res.error_for_status()?;
    let value = res.json::<u8>().await?;
    let result = if value == 1 { true } else { false };
    Ok(result)
}

/// Check a collection of SHA1 hashes.
#[instrument(skip_all)]
pub async fn batch(
    hashes: &[String],
    host: Option<String>,
) -> Result<Vec<bool>> {
    if is_offline() {
        tracing::warn!("offline mode active, ignoring batch hashcheck");
        return Ok(hashes.iter().map(|_| false).collect());
    }

    let host = host.unwrap_or_else(|| ENDPOINT.to_owned());

    tracing::info!(host = %host, "hashcheck");

    let url = format!("{}/", host);
    let client = reqwest::Client::new();
    let res = client.post(url).json(&hashes).send().await?;
    tracing::debug!(status = %res.status(), "hashcheck");
    let res = res.error_for_status()?;
    let value = res.json::<Vec<u8>>().await?;
    let result = value
        .into_iter()
        .map(|value| if value == 1 { true } else { false })
        .collect();
    Ok(result)
}
