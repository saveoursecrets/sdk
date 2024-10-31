use super::AccountSwitcher;
use crate::{
    account::Account,
    prelude::{Identity, PublicIdentity},
};
use async_trait::async_trait;

/// List of accounts with authenticated status flag.
pub type AccountsList = Vec<(PublicIdentity, bool)>;

/// Contract for types that expose an API to
/// app integrations such as browser extensions.
#[async_trait]
pub trait AppIntegration<E: From<crate::Error>> {
    /// List the accounts on disc and include authentication state.
    async fn list_accounts(
        &mut self,
    ) -> Result<Vec<(PublicIdentity, bool)>, E>;
}

#[async_trait]
impl<E, R, A> AppIntegration<E> for AccountSwitcher<E, R, A>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    E: From<crate::Error>,
{
    async fn list_accounts(&mut self) -> Result<AccountsList, E> {
        let mut out = Vec::new();
        let disc_accounts =
            Identity::list_accounts(self.data_dir.as_ref()).await?;
        for account in disc_accounts {
            let authenticated = if let Some(memory_account) = self
                .accounts
                .iter()
                .find(|a| a.address() == account.address())
            {
                memory_account.is_authenticated().await
            } else {
                false
            };

            out.push((account, authenticated));
        }
        Ok(out)
    }
}
