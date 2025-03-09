use anyhow::Result;
use futures::{pin_mut, StreamExt};
use sos_audit::{AuditData, AuditEvent};
use sos_backend::audit::AuditProvider;
use sos_core::{events::EventKind, AccountId, SecretId, VaultId};

/// Assert on audit providers.
pub async fn assert_audit_provider(
    provider: &mut AuditProvider,
) -> Result<()> {
    let account_id = AccountId::random();
    let folder_id = VaultId::new_v4();
    let secret_id = SecretId::new_v4();
    let events = vec![
        AuditEvent::new(
            Default::default(),
            EventKind::CreateAccount,
            account_id,
            None,
        ),
        AuditEvent::new(
            Default::default(),
            EventKind::CreateVault,
            account_id,
            Some(AuditData::Vault(folder_id)),
        ),
        AuditEvent::new(
            Default::default(),
            EventKind::CreateSecret,
            account_id,
            Some(AuditData::Secret(folder_id, secret_id)),
        ),
        AuditEvent::new(
            Default::default(),
            EventKind::DeleteAccount,
            account_id,
            None,
        ),
    ];

    // Append audit events
    provider.append_audit_events(events.as_slice()).await?;

    // Read events from the provider stream in insertion order
    let stream = provider.audit_stream(false).await?;
    pin_mut!(stream);
    let event_list = stream.collect::<Vec<_>>().await;
    assert_eq!(events.len(), event_list.len());
    let mut audit_events = Vec::new();
    for event in event_list {
        audit_events.push(event?);
    }
    assert_eq!(events, audit_events);

    // Read events from the provider stream in reverse order
    let stream = provider.audit_stream(true).await?;
    pin_mut!(stream);
    let event_list = stream.collect::<Vec<_>>().await;
    assert_eq!(events.len(), event_list.len());
    let mut audit_events = Vec::new();
    for event in event_list {
        audit_events.push(event?);
    }
    // Reverse the reversed list for comparion with original
    audit_events.reverse();
    assert_eq!(events, audit_events);

    Ok(())
}
