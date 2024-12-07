use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use crate::{
    account::{Account, LocalAccount},
    identity::Identity,
    prelude::{Address, PublicIdentity},
    Paths, Result,
};

/// Account switcher for local accounts.
pub type LocalAccountSwitcher = AccountSwitcher<
    LocalAccount,
    <LocalAccount as Account>::NetworkResult,
    <LocalAccount as Account>::Error,
>;

/// Collection of accounts with a currently selected account.
///
/// Allows multiple accounts to be authenticated concurrently
/// so that integrations are able to operate on multiple accounts
/// provided they are authenticated.
pub struct AccountSwitcher<A, R, E>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    E: From<crate::Error> + std::fmt::Debug,
{
    #[doc(hidden)]
    pub accounts: Vec<A>,
    selected: Option<Address>,
    data_dir: Option<Paths>,
}

impl<A, R, E> AccountSwitcher<A, R, E>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    E: From<crate::Error> + std::fmt::Debug,
{
    /// Create an account switcher.
    pub fn new() -> Self {
        Self {
            accounts: Default::default(),
            selected: None,
            data_dir: None,
        }
    }

    /// Data directory.
    pub fn data_dir(&self) -> Option<&Paths> {
        self.data_dir.as_ref()
    }

    /// Accounts iterator.
    pub fn iter<'a>(&'a self) -> std::slice::Iter<'a, A> {
        self.accounts.iter()
    }

    /// Mutable accounts iterator.
    pub fn iter_mut<'a>(&'a mut self) -> std::slice::IterMut<'a, A> {
        self.accounts.iter_mut()
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

    /// Load accounts from disc and add them.
    pub async fn load_accounts<B>(
        &mut self,
        builder: B,
        data_dir: Option<PathBuf>,
    ) -> Result<()>
    where
        B: Fn(
            PublicIdentity,
        )
            -> Pin<Box<dyn Future<Output = std::result::Result<A, E>>>>,
    {
        Paths::scaffold(data_dir.clone()).await?;

        let identities = Identity::list_accounts(self.data_dir()).await?;

        for identity in identities {
            tracing::info!(address = %identity.address(), "add_account");
            let account = builder(identity).await.unwrap();

            let paths = account.paths();
            // tracing::info!(paths = ?paths);
            paths.ensure().await?;
            self.add_account(account);
        }
        Ok(())
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
    pub async fn sign_out_all(&mut self) -> std::result::Result<(), E> {
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
