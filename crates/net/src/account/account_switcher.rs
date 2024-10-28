use crate::{
    account::NetworkAccount,
    sdk::prelude::{Account, Address, Identity, PublicIdentity},
    Result,
};

/// Collection of accounts with a currently selected account.
///
/// Allows multiple accounts to be authenticated concurrently
/// so that integrations are able to operate on multiple accounts
/// provided they are authenticated.
#[derive(Default)]
pub struct AccountSwitcher {
    accounts: Vec<NetworkAccount>,
    selected: Option<Address>,
}

impl AccountSwitcher {
    /// List local accounts.
    pub async fn list_accounts() -> Result<Vec<PublicIdentity>> {
        Ok(Identity::list_accounts(None).await?)
    }

    /// Add an account to the collection.
    pub fn add_account(&mut self, account: NetworkAccount) {
        self.accounts.push(account);
    }

    /// Remove an account from the collection.
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
    pub fn selected_account(&self) -> Option<&NetworkAccount> {
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
    pub fn selected_account_mut(&mut self) -> Option<&mut NetworkAccount> {
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
