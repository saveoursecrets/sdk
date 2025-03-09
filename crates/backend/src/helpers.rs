use crate::Result;
use sos_core::{
    decode,
    events::{EventRecord, WriteEvent},
};
use sos_vault::Vault;

/// Extract a vault from the first write event in
/// a collection of records.
#[doc(hidden)]
pub async fn extract_vault(records: &[EventRecord]) -> Result<Option<Vault>> {
    let first_record = records.get(0);
    Ok(if let Some(record) = first_record {
        let event: WriteEvent = record.decode_event().await?;
        let WriteEvent::CreateVault(buf) = event else {
            return Err(sos_core::Error::CreateEventMustBeFirst.into());
        };
        let vault: Vault = decode(&buf).await?;
        Some(vault)
    } else {
        None
    })
}
