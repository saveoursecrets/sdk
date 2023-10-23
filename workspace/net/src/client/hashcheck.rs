//! Check password hashes using the hashcheck service.
use super::Result;

/// Default endpoint for HIBP database checks.
const ENDPOINT: &str = "https://hashcheck.saveoursecrets.com";

/// Check a single SHA1 hash of a password exists in the HIBP
/// database by calling an endpoint.
pub async fn single(
    password_hash: String,
    host: Option<String>,
) -> Result<bool> {
    let host = host.unwrap_or_else(|| ENDPOINT.to_owned());
    tracing::info!(host = %host, "hashcheck");
    let url = format!("{}/{}", host, password_hash.to_uppercase());
    let client = reqwest::Client::new();
    let res = client.get(url).send().await?;
    tracing::debug!(
        status = %res.status(), "hashcheck response status (single)");
    let res = res.error_for_status()?;
    let value = res.json::<u8>().await?;
    let result = if value == 1 { true } else { false };
    Ok(result)
}

/// Check a collection of SHA1 hashes.
pub async fn batch(
    hashes: Vec<String>,
    host: Option<String>,
) -> Result<Vec<bool>> {
    let host = host.unwrap_or_else(|| ENDPOINT.to_owned());
    tracing::info!(host = %host, "hashcheck");
    let url = format!("{}/", host);
    let client = reqwest::Client::new();
    let res = client.post(url).json(&hashes).send().await?;
    tracing::debug!(
        status = %res.status(), "hashcheck response status (batch)");
    let res = res.error_for_status()?;
    let value = res.json::<Vec<u8>>().await?;
    let result = value
        .into_iter()
        .map(|value| if value == 1 { true } else { false })
        .collect();
    Ok(result)
}
