//! Event for trusting and revoking devices.
use super::{EventKind, LogEvent};
use crate::device::{DevicePublicKey, TrustedDevice};

/// Device event records trust and revocation of account devices.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub enum DeviceEvent {
    #[default]
    #[doc(hidden)]
    Noop,
    /// Device was trusted.
    Trust(TrustedDevice),
    /// Device had it's trustworhtiness revoked.
    ///
    /// Typically this would occur when a device is lost
    /// or stolen.
    Revoke(DevicePublicKey),
}

impl LogEvent for DeviceEvent {
    fn event_kind(&self) -> EventKind {
        match self {
            Self::Noop => EventKind::Noop,
            Self::Trust(_) => EventKind::TrustDevice,
            Self::Revoke(_) => EventKind::RevokeDevice,
        }
    }
}
