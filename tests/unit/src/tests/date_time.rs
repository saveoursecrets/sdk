use anyhow::Result;
use sos_sdk::{decode, encode, UtcDateTime};

#[tokio::test]
async fn date_time_encode_decode() -> Result<()> {
    let timestamp: UtcDateTime = Default::default();
    let buffer = encode(&timestamp).await?;
    let decoded: UtcDateTime = decode(&buffer).await?;
    assert_eq!(timestamp, decoded);
    Ok(())
}
