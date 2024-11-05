use async_trait::async_trait;
use sos_net::sdk::prelude::{Address, PublicIdentity};
use std::time::Duration;

use crate::CommandOutcome;

/// List of accounts with authenticated status flag.
pub type AccountsList = Vec<(PublicIdentity, bool)>;

/// Contract for types that expose an API to
/// app integrations such as browser extensions.
#[async_trait]
pub trait AppIntegration<E: From<sos_net::sdk::Error>> {
    /// Ping the server.
    async fn ping(&mut self) -> Result<Duration, E>;

    /// List the accounts on disc and include authentication state.
    async fn list_accounts(
        &mut self,
    ) -> Result<Vec<(PublicIdentity, bool)>, E>;

    /// Attempt to authenticate an account.
    async fn authenticate(
        &mut self,
        address: Address,
    ) -> Result<CommandOutcome, E>;

    /// Attempt to lock an account.
    async fn lock(
        &mut self,
        address: Option<Address>,
    ) -> Result<CommandOutcome, E>;
}
