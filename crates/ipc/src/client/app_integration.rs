use async_trait::async_trait;
use sos_net::sdk::prelude::{Address, PublicIdentity};

use crate::AuthenticateOutcome;

/// List of accounts with authenticated status flag.
pub type AccountsList = Vec<(PublicIdentity, bool)>;

/// Contract for types that expose an API to
/// app integrations such as browser extensions.
#[async_trait]
pub trait AppIntegration<E: From<sos_net::sdk::Error>> {
    /// List the accounts on disc and include authentication state.
    async fn list_accounts(
        &mut self,
    ) -> Result<Vec<(PublicIdentity, bool)>, E>;

    /// Attempt to authenticate an account.
    async fn authenticate(
        &mut self,
        address: Address,
    ) -> Result<AuthenticateOutcome, E>;
}
