use anyhow::Result;

use sos_net::{
    protocol::{
        DiffRequest, DiffResponse, PatchRequest, PatchResponse, ScanRequest,
        ScanResponse, WireEncodeDecode,
    },
    sdk::{
        commit::{CommitHash, CommitProof, CommitState},
        events::EventRecord,
        sync::CheckedPatch,
        UtcDateTime,
    },
};
use sos_sdk::events::EventLogType;

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

#[test]
fn encode_decode_diff_request() -> Result<()> {
    let hash: CommitHash = HASH.parse()?;
    let value = DiffRequest {
        log_type: EventLogType::Identity,
        from_hash: Some(hash),
    };

    let buffer = value.clone().encode()?;
    let decoded = DiffRequest::decode(buffer.as_slice())?;
    assert_eq!(value, decoded);

    Ok(())
}

#[test]
fn encode_decode_diff_response() -> Result<()> {
    let mock = "event-record-data";
    let last_commit: CommitHash = HASH.parse()?;
    let commit: CommitHash = HASH.parse()?;
    let record = EventRecord::new(
        UtcDateTime::default(),
        last_commit,
        commit,
        mock.as_bytes().to_vec(),
    );

    let value = DiffResponse {
        patch: vec![record],
        checkpoint: Default::default(),
    };

    let buffer = value.clone().encode()?;
    let decoded = DiffResponse::decode(buffer.as_slice())?;
    assert_eq!(value, decoded);

    Ok(())
}

#[test]
fn encode_decode_scan_request() -> Result<()> {
    let value = ScanRequest {
        log_type: EventLogType::Identity,
        limit: 32,
        offset: 16,
    };

    let buffer = value.clone().encode()?;
    let decoded = ScanRequest::decode(buffer.as_slice())?;
    assert_eq!(value, decoded);

    Ok(())
}

#[test]
fn encode_decode_scan_response() -> Result<()> {
    let value = ScanResponse {
        first_proof: Default::default(),
        offset: 32,
        proofs: vec![Default::default()],
    };

    let buffer = value.clone().encode()?;
    let decoded = ScanResponse::decode(buffer.as_slice())?;
    assert_eq!(value, decoded);

    Ok(())
}

#[test]
fn encode_decode_patch_request() -> Result<()> {
    let mock = "event-record-data";
    let last_commit: CommitHash = HASH.parse()?;
    let commit: CommitHash = HASH.parse()?;
    let record = EventRecord::new(
        UtcDateTime::default(),
        last_commit,
        commit,
        mock.as_bytes().to_vec(),
    );

    let value = PatchRequest {
        log_type: EventLogType::Identity,
        patch: vec![record],
        commit: Some(Default::default()),
        proof: Default::default(),
    };

    let buffer = value.clone().encode()?;
    let decoded = PatchRequest::decode(buffer.as_slice())?;
    assert_eq!(value, decoded);

    Ok(())
}

#[test]
fn encode_decode_patch_response() -> Result<()> {
    let checked_patch = CheckedPatch::Success(Default::default());
    let value = PatchResponse { checked_patch };
    let buffer = value.clone().encode()?;
    let decoded = PatchResponse::decode(buffer.as_slice())?;
    assert_eq!(value, decoded);

    Ok(())
}
