use anyhow::Result;

use sos_net::{
    protocol::WireEncodeDecode,
    sdk::{
        commit::{CommitHash, CommitProof, CommitState},
        events::EventRecord,
        sync::CheckedPatch,
        UtcDateTime,
    },
};

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

#[test]
fn encode_decode_commit_proof() -> Result<()> {
    let value = CommitProof::default();
    let buffer = value.clone().encode()?;
    let decoded = CommitProof::decode(buffer.as_slice())?;
    assert_eq!(value, decoded);
    Ok(())
}

#[test]
fn encode_decode_commit_state() -> Result<()> {
    let value = CommitState::default();
    let buffer = value.clone().encode()?;
    let decoded = CommitState::decode(buffer.as_slice())?;
    assert_eq!(value, decoded);
    Ok(())
}

#[test]
fn encode_decode_event_record() -> Result<()> {
    let mock = "event-record-data";
    let last_commit: CommitHash = HASH.parse()?;
    let commit: CommitHash = HASH.parse()?;
    let value = EventRecord::new(
        UtcDateTime::default(),
        last_commit,
        commit,
        mock.as_bytes().to_vec(),
    );
    let buffer = value.clone().encode()?;
    let decoded = EventRecord::decode(buffer.as_slice())?;
    assert_eq!(value, decoded);
    assert_eq!(mock.as_bytes(), decoded.event_bytes());
    Ok(())
}

#[test]
fn encode_decode_checked_patch() -> Result<()> {
    let value = CheckedPatch::Success(Default::default());
    let buffer = value.clone().encode()?;
    let decoded = CheckedPatch::decode(buffer.as_slice())?;
    assert_eq!(value, decoded);

    let value = CheckedPatch::Conflict {
        head: Default::default(),
        contains: None,
    };
    let buffer = value.clone().encode()?;
    let decoded = CheckedPatch::decode(buffer.as_slice())?;
    assert_eq!(value, decoded);

    let value = CheckedPatch::Conflict {
        head: Default::default(),
        contains: Some(Default::default()),
    };
    let buffer = value.clone().encode()?;
    let decoded = CheckedPatch::decode(buffer.as_slice())?;
    assert_eq!(value, decoded);

    Ok(())
}
