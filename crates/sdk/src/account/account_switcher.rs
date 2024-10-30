use crate::{
    account::{Account, LocalAccount},
    prelude::{Address, Identity, PublicIdentity},
    Paths,
};
use async_trait::async_trait;

/// Account switcher for local accounts.
pub type LocalAccountSwitcher = AccountSwitcher<
    <LocalAccount as Account>::Error,
    <LocalAccount as Account>::NetworkResult,
    LocalAccount,
>;

/// Describes the contract for types that expose an API to
/// app integrations such as browser extensions.
#[async_trait]
pub trait AppIntegration<E: From<crate::Error>> {
    /// List the accounts on disc and include authentication state.
    async fn list_accounts(
        &mut self,
    ) -> Result<Vec<(PublicIdentity, bool)>, E>;
}

/// Collection of accounts with a currently selected account.
///
/// Allows multiple accounts to be authenticated concurrently
/// so that integrations are able to operate on multiple accounts
/// provided they are authenticated.
pub struct AccountSwitcher<E, R, A>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    E: From<crate::Error>,
{
    accounts: Vec<A>,
    selected: Option<Address>,
    data_dir: Option<Paths>,
}

impl<E, R, A> AccountSwitcher<E, R, A>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    E: From<crate::Error>,
{
    /// Create an account switcher.
    pub fn new() -> Self {
        Self {
            accounts: Default::default(),
            selected: None,
            data_dir: None,
        }
    }

    /// Create an account switcher with a data directory.
    pub fn new_with_options(data_dir: Option<Paths>) -> Self {
        Self {
            accounts: Default::default(),
            selected: None,
            data_dir,
        }
    }

    /// Number of accounts.
    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    /// Add an account if it does not already exist and make
    /// it the selected account.
    ///
    /// If the account already exists it is selected.
    pub fn new_account(&mut self, account: A) -> bool {
        let address = *account.address();
        if self.add_account(account) {
            self.selected = Some(address);
            true
        } else {
            self.selected = Some(address);
            false
        }
    }

    /// Add an account to the collection if it does not already exist.
    pub fn add_account(&mut self, account: A) -> bool {
        if self.position(account.address()).is_none() {
            self.accounts.push(account);
            true
        } else {
            false
        }
    }

    /// Remove an account from the collection if it exists.
    pub fn remove_account(&mut self, address: &Address) -> bool {
        if let Some(position) = self.position(address) {
            self.accounts.remove(position);
            if self.selected == Some(*address) {
                self.selected = None;
            }
            true
        } else {
            false
        }
    }

    /// Switch selected account.
    ///
    /// If no account exists for the given address no change
    /// is made to the current selection.
    pub fn switch_account(&mut self, address: &Address) -> bool {
        if self.position(address).is_some() {
            self.selected = Some(*address);
            true
        } else {
            false
        }
    }

    /// Selected account.
    pub fn selected_account(&self) -> Option<&A> {
        if let Some(address) = &self.selected {
            if let Some(index) = self.position(address) {
                self.accounts.get(index)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Mutable selected account.
    pub fn selected_account_mut(&mut self) -> Option<&mut A> {
        if let Some(address) = &self.selected {
            if let Some(index) = self.position(address) {
                self.accounts.get_mut(index)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Sign out of all authenticated accounts.
    pub async fn sign_out_all(&mut self) -> Result<(), E> {
        for account in &mut self.accounts {
            if account.is_authenticated().await {
                tracing::info!(account = %account.address(), "sign out");
                account.sign_out().await?;
            }
        }
        Ok(())
    }

    fn position(&self, address: &Address) -> Option<usize> {
        self.accounts.iter().position(|a| a.address() == address)
    }
}

#[async_trait]
impl<E, R, A> AppIntegration<E> for AccountSwitcher<E, R, A>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    E: From<crate::Error>,
{
    async fn list_accounts(
        &mut self,
    ) -> Result<Vec<(PublicIdentity, bool)>, E> {
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
