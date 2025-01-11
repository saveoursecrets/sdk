use futures::{pin_mut, stream::StreamExt};
use indexmap::IndexSet;
use sos_core::events::EventLog;
use sos_core::{device::TrustedDevice, events::DeviceEvent};

/// Reduce device events to a collection of devices.
pub struct DeviceReducer<'a, L, E>
where
    L: EventLog<DeviceEvent, Error = E>,
    E: std::error::Error + std::fmt::Debug + From<sos_core::Error>,
{
    log: &'a L,
}

impl<'a, L, E> DeviceReducer<'a, L, E>
where
    L: EventLog<DeviceEvent, Error = E>,
    E: std::error::Error + std::fmt::Debug + From<sos_core::Error>,
{
    /// Create a new device reducer.
    pub fn new(log: &'a L) -> Self {
        Self { log }
    }

    /// Reduce device events to a canonical collection
    /// of trusted devices.
    pub async fn reduce(self) -> Result<IndexSet<TrustedDevice>, E> {
        let mut devices = IndexSet::new();

        let stream = self.log.event_stream(false).await;
        pin_mut!(stream);

        while let Some(event) = stream.next().await {
            let (_, event) = event?;

            match event {
                DeviceEvent::Trust(device) => {
                    devices.insert(device);
                }
                DeviceEvent::Revoke(public_key) => {
                    let device = devices
                        .iter()
                        .find(|d| d.public_key() == &public_key)
                        .cloned();
                    if let Some(device) = device {
                        devices.shift_remove(&device);
                    }
                }
                _ => {}
            }
        }
        Ok(devices)
    }
}
