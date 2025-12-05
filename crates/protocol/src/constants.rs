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

        /// Route for set and get recipient information.
        pub const SHARING_RECIPIENT: &str = "/api/v1/sharing/recipient";

        /// Route for creating a shared folder.
        pub const SHARING_CREATE_FOLDER: &str = "/api/v1/sharing/folder";

        /// Route for listing sent invites.
        pub const SHARING_SENT_INVITES: &str =
            "/api/v1/sharing/folder/invites/sent";

        /// Route for listing received invites.
        pub const SHARING_RECEIVED_INVITES: &str =
            "/api/v1/sharing/folder/invites/inbox";

        /// Route for updating folder invite.
        pub const SHARING_UPDATE_INVITE: &str =
            "/api/v1/sharing/folder/invites";
    }
}

pub use header::*;
pub use mime::*;
