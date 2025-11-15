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
    Ok(if let Some(record) = records.first() {
        let event: WriteEvent = record.decode_event().await?;
        let WriteEvent::CreateVault(buf) = event else {
            return Err(sos_core::Error::CreateEventMustBeFirst.into());
        };
        decode(&buf).await?
    } else {
        None
    })
}
