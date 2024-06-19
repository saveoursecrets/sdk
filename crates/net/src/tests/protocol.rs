//! Basic smoke tests for encoding and decoding.
use anyhow::Result;
use prost::bytes::Bytes;

use crate::{
    protocol::{
        sync::{EventLogType, MergeOutcome},
        DiffRequest, DiffResponse, PatchRequest, PatchResponse, ScanRequest,
        ScanResponse, WireEncodeDecode,
    },
    sdk::{
        commit::{CommitHash, CommitProof, CommitState},
        events::{CheckedPatch, EventRecord},
        signer::ecdsa::Address,
        vault::VaultId,
        UtcDateTime,
    },
};

const HASH: &str =
    "54c4de4a0db65b62302964a52b0ea346e69b11d54b430d4615672a37ff0d4e58";

#[tokio::test]
async fn encode_decode_utc_date_time() -> Result<()> {
    let value = UtcDateTime::default();
    let buffer = value.clone().encode().await?;
    let buffer: Bytes = buffer.into();
    let decoded = UtcDateTime::decode(buffer).await?;
    assert_eq!(value, decoded);
    Ok(())
}

#[tokio::test]
async fn encode_decode_commit_hash() -> Result<()> {
    let value: CommitHash = HASH.parse()?;
    let buffer = value.encode().await?;
    let buffer: Bytes = buffer.into();
    let decoded = CommitHash::decode(buffer).await?;
    assert_eq!(value, decoded);
    Ok(())
}

#[tokio::test]
async fn encode_decode_commit_proof() -> Result<()> {
    let value = CommitProof::default();
    let buffer = value.clone().encode().await?;
    let buffer: Bytes = buffer.into();
    let decoded = CommitProof::decode(buffer).await?;
    assert_eq!(value, decoded);
    Ok(())
}

#[tokio::test]
async fn encode_decode_commit_state() -> Result<()> {
    let value = CommitState::default();
    let buffer = value.clone().encode().await?;
    let buffer: Bytes = buffer.into();
    let decoded = CommitState::decode(buffer).await?;
    assert_eq!(value, decoded);
    Ok(())
}

#[tokio::test]
async fn encode_decode_event_record() -> Result<()> {
    let mock = "event-record-data";
    let last_commit: CommitHash = HASH.parse()?;
    let commit: CommitHash = HASH.parse()?;
    let value = EventRecord::new(
        UtcDateTime::default(),
        last_commit,
        commit,
        mock.as_bytes().to_vec(),
    );
    let buffer = value.clone().encode().await?;
    let buffer: Bytes = buffer.into();
    let decoded = EventRecord::decode(buffer).await?;
    assert_eq!(value, decoded);
    assert_eq!(mock.as_bytes(), decoded.event_bytes());
    Ok(())
}

#[tokio::test]
async fn encode_decode_checked_patch() -> Result<()> {
    let value = CheckedPatch::Success(Default::default());
    let buffer = value.clone().encode().await?;
    let buffer: Bytes = buffer.into();
    let decoded = CheckedPatch::decode(buffer).await?;
    assert_eq!(value, decoded);

    let value = CheckedPatch::Conflict {
        head: Default::default(),
        contains: None,
    };
    let buffer = value.clone().encode().await?;
    let buffer: Bytes = buffer.into();
    let decoded = CheckedPatch::decode(buffer).await?;
    assert_eq!(value, decoded);

    let value = CheckedPatch::Conflict {
        head: Default::default(),
        contains: Some(Default::default()),
    };
    let buffer = value.clone().encode().await?;
    let buffer: Bytes = buffer.into();
    let decoded = CheckedPatch::decode(buffer).await?;
    assert_eq!(value, decoded);

    Ok(())
}

#[tokio::test]
async fn encode_decode_diff_request() -> Result<()> {
    let hash: CommitHash = HASH.parse()?;
    let value = DiffRequest {
        log_type: EventLogType::Identity,
        from_hash: Some(hash),
    };

    let buffer = value.clone().encode().await?;
    let buffer: Bytes = buffer.into();
    let decoded = DiffRequest::decode(buffer).await?;
    assert_eq!(value, decoded);

    Ok(())
}

#[tokio::test]
async fn encode_decode_diff_response() -> Result<()> {
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

    let buffer = value.clone().encode().await?;
    let buffer: Bytes = buffer.into();
    let decoded = DiffResponse::decode(buffer).await?;
    assert_eq!(value, decoded);

    Ok(())
}

#[tokio::test]
async fn encode_decode_scan_request() -> Result<()> {
    let value = ScanRequest {
        log_type: EventLogType::Identity,
        limit: 32,
        offset: 16,
    };

    let buffer = value.clone().encode().await?;
    let buffer: Bytes = buffer.into();
    let decoded = ScanRequest::decode(buffer).await?;
    assert_eq!(value, decoded);

    Ok(())
}

#[tokio::test]
async fn encode_decode_scan_response() -> Result<()> {
    let value = ScanResponse {
        first_proof: Default::default(),
        offset: 32,
        proofs: vec![Default::default()],
    };

    let buffer = value.clone().encode().await?;
    let buffer: Bytes = buffer.into();
    let decoded = ScanResponse::decode(buffer).await?;
    assert_eq!(value, decoded);

    Ok(())
}

#[tokio::test]
async fn encode_decode_patch_request() -> Result<()> {
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

    let buffer = value.clone().encode().await?;
    let buffer: Bytes = buffer.into();
    let decoded = PatchRequest::decode(buffer).await?;
    assert_eq!(value, decoded);

    Ok(())
}

#[tokio::test]
async fn encode_decode_patch_response() -> Result<()> {
    let checked_patch = CheckedPatch::Success(Default::default());
    let value = PatchResponse { checked_patch };
    let buffer = value.clone().encode().await?;
    let buffer: Bytes = buffer.into();
    let decoded = PatchResponse::decode(buffer).await?;
    assert_eq!(value, decoded);

    Ok(())
}

#[tokio::test]
async fn encode_decode_merge_outcom() -> Result<()> {
    let value = MergeOutcome {
        changes: 13,
        ..Default::default()
    };
    let buffer = value.clone().encode().await?;
    let buffer: Bytes = buffer.into();
    let decoded = MergeOutcome::decode(buffer).await?;
    assert_eq!(value, decoded);

    Ok(())
}

#[cfg(feature = "listen")]
#[tokio::test]
async fn encode_decode_change_notification() -> Result<()> {
    use crate::protocol::ChangeNotification;
    let outcome = MergeOutcome {
        changes: 7,
        ..Default::default()
    };
    let address: Address = [1u8; 20].into();
    let value = ChangeNotification::new(
        &address,
        "mock-connection".to_string(),
        Default::default(),
        outcome,
    );
    let buffer = value.clone().encode().await?;
    let buffer: Bytes = buffer.into();
    let decoded = ChangeNotification::decode(buffer).await?;
    assert_eq!(value, decoded);

    Ok(())
}

#[tokio::test]
async fn encode_decode_event_log_type_system() -> Result<()> {
    let value = EventLogType::Identity;
    let buffer = value.clone().encode().await?;
    let buffer: Bytes = buffer.into();
    let decoded = EventLogType::decode(buffer).await?;
    assert_eq!(value, decoded);

    Ok(())
}

#[tokio::test]
async fn encode_decode_event_log_type_user() -> Result<()> {
    let value = EventLogType::Folder(VaultId::new_v4());
    let buffer = value.clone().encode().await?;
    let buffer: Bytes = buffer.into();
    let decoded = EventLogType::decode(buffer).await?;
    assert_eq!(value, decoded);

    Ok(())
}

#[cfg(feature = "files")]
#[tokio::test]
async fn encode_decode_change_files() -> Result<()> {
    use crate::{
        protocol::sync::{FileSet, FileTransfersSet},
        sdk::{storage::files::ExternalFile, vault::secret::SecretId},
    };
    use indexmap::IndexSet;

    let file_name = [1u8; 32];

    let mut up = IndexSet::new();
    up.insert(ExternalFile::new(
        VaultId::new_v4(),
        SecretId::new_v4(),
        file_name.into(),
    ));
    let mut down = IndexSet::new();
    down.insert(ExternalFile::new(
        VaultId::new_v4(),
        SecretId::new_v4(),
        file_name.into(),
    ));

    let uploads = FileSet(up);
    let downloads = FileSet(down);

    let value = FileTransfersSet { uploads, downloads };
    let buffer = value.clone().encode().await?;
    let buffer: Bytes = buffer.into();
    let decoded = FileTransfersSet::decode(buffer).await?;
    assert_eq!(value, decoded);

    Ok(())
}
