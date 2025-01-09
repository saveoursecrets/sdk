mod device {
    use crate::events::EventLog;
    use futures::{pin_mut, stream::StreamExt};
    use indexmap::IndexSet;
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

            let stream = self.log.stream(false).await;
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
}

pub use device::DeviceReducer;

#[cfg(feature = "files")]
mod files {
    use crate::events::EventLog;
    use futures::{pin_mut, stream::StreamExt};
    use indexmap::IndexSet;
    use sos_core::commit::CommitHash;
    use sos_core::events::FileEvent;
    use sos_core::ExternalFile;

    /// Reduce file events to a collection of external files.
    pub struct FileReducer<'a, L, E>
    where
        L: EventLog<FileEvent, Error = E>,
        E: std::error::Error + std::fmt::Debug + From<sos_core::Error>,
    {
        log: &'a L,
    }

    impl<'a, L, E> FileReducer<'a, L, E>
    where
        L: EventLog<FileEvent, Error = E>,
        E: std::error::Error + std::fmt::Debug + From<sos_core::Error>,
    {
        /// Create a new file reducer.
        pub fn new(log: &'a L) -> Self {
            Self { log }
        }

        fn add_file_event(
            &self,
            event: FileEvent,
            files: &mut IndexSet<ExternalFile>,
        ) {
            match event {
                FileEvent::CreateFile(owner, file_name) => {
                    files.insert(ExternalFile::new(owner, file_name));
                }
                FileEvent::MoveFile { name, from, dest } => {
                    let file = ExternalFile::new(from, name);
                    files.shift_remove(&file);
                    files.insert(ExternalFile::new(dest, name));
                }
                FileEvent::DeleteFile(owner, file_name) => {
                    let file = ExternalFile::new(owner, file_name);
                    files.shift_remove(&file);
                }
                _ => {}
            }
        }

        /// Reduce file events to a canonical collection
        /// of external files.
        pub async fn reduce(
            self,
            from: Option<&CommitHash>,
        ) -> Result<IndexSet<ExternalFile>, E> {
            let mut files: IndexSet<ExternalFile> = IndexSet::new();

            // Reduce from the target commit.
            //
            // When reducing from a target commit we perform
            // a diff as this reads from the tail of the event
            // log which will be faster than scanning when there
            // are lots of file events.
            if let Some(from) = from {
                let patch = self.log.diff_events(Some(from)).await?;
                for record in patch.iter() {
                    let event = record.decode_event::<FileEvent>().await?;
                    self.add_file_event(event, &mut files);
                }
            } else {
                let stream = self.log.stream(false).await;
                pin_mut!(stream);

                while let Some(event) = stream.next().await {
                    let (_, event) = event?;
                    self.add_file_event(event, &mut files);
                }
            }

            Ok(files)
        }
    }
}

#[cfg(feature = "files")]
pub use files::FileReducer;
