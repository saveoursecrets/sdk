//! Constants for the networking protocols.

/// Constants for MIME types.
mod mime {
    /// Mime type for protocol buffers.
    pub const MIME_TYPE_PROTOBUF: &str = "application/x-protobuf";

    /// Mime type for JSON.
    pub const MIME_TYPE_JSON: &str = "application/json";
}

/// Constants for header names or values.
mod header {
    /// Header name used to specify an account address.
    pub const X_SOS_ACCOUNT_ID: &str = "x-sos-account-id";

    /// Header name used to specify a request id.
    pub const X_SOS_REQUEST_ID: &str = "x-sos-request-id";
}

/// Route paths.
pub mod routes {
    /// Routes for v1.
    pub mod v1 {

        /// List accounts; local IPC server only.
        pub const ACCOUNTS_LIST: &str = "/api/v1/accounts";

        /// Route for syncing account data.
        pub const SYNC_ACCOUNT: &str = "/api/v1/sync/account";

        /// Route for sync account status.
        pub const SYNC_ACCOUNT_STATUS: &str = "/api/v1/sync/account/status";

        /// Route for syncing account events.
        pub const SYNC_ACCOUNT_EVENTS: &str = "/api/v1/sync/account/events";
    }
}

pub use header::*;
pub use mime::*;
