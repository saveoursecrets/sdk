use anyhow::Result;

use sos_net::{protocol::WireEncodeDecode, sdk::commit::CommitHash};
use sos_sdk::UtcDateTime;

const HASH: &str =
    "54c4de4a0db65b62302964a52b0ea346e69b11d54b430d4615672a37ff0d4e58";

#[test]
fn encode_decode_utc_date_time() -> Result<()> {
    let value = UtcDateTime::default();
    let buffer = value.clone().encode()?;
    let decoded = UtcDateTime::decode(buffer.as_slice())?;
    assert_eq!(value, decoded);
    Ok(())
}

#[test]
fn encode_decode_commit_hash() -> Result<()> {
    let value: CommitHash = HASH.parse()?;
    let buffer = value.encode()?;
    let decoded = CommitHash::decode(buffer.as_slice())?;
    assert_eq!(value, decoded);
    Ok(())
}
