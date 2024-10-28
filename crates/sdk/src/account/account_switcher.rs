use crate::{
    account::{Account, LocalAccount},
    prelude::Address,
};

/// Account switcher for local accounts.
pub type LocalAccountSwitcher = AccountSwitcher<
    <LocalAccount as Account>::Error,
    <LocalAccount as Account>::NetworkResult,
    LocalAccount,
>;

/// Collection of accounts with a currently selected account.
///
/// Allows multiple accounts to be authenticated concurrently
/// so that integrations are able to operate on multiple accounts
/// provided they are authenticated.
pub struct AccountSwitcher<E, R, A: Account<Error = E, NetworkResult = R>> {
    accounts: Vec<A>,
    selected: Option<Address>,
}

impl<E, R, A: Account<Error = E, NetworkResult = R>>
    AccountSwitcher<E, R, A>
{
    /// Create an account switcher.
    pub fn new() -> Self {
        Self {
            accounts: Default::default(),
            selected: None,
        }
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

    fn position(&self, address: &Address) -> Option<usize> {
        self.accounts.iter().position(|a| a.address() == address)
    }
}
