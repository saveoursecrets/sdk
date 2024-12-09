use std::path::PathBuf;
use std::pin::Pin;
use std::{collections::HashMap, future::Future};

use crate::{
    account::{Account, LocalAccount},
    identity::Identity,
    prelude::{
        Address, ArchiveFilter, Document, DocumentView, PublicIdentity,
        QueryFilter,
    },
    Paths, Result,
};

#[cfg(feature = "clipboard")]
use xclipboard::Clipboard;

#[cfg(feature = "clipboard")]
use crate::prelude::SecretPath;

/// Account switcher for local accounts.
pub type LocalAccountSwitcher = AccountSwitcher<
    LocalAccount,
    <LocalAccount as Account>::NetworkResult,
    <LocalAccount as Account>::Error,
>;

/// Options for an account switcher.
#[derive(Default)]
pub struct AccountSwitcherOptions {
    /// Paths for data storage.
    pub paths: Option<Paths>,
    /// Clipboard backend.
    #[cfg(feature = "clipboard")]
    pub clipboard: Option<Clipboard>,
}

/// Collection of accounts with a currently selected account.
///
/// Allows multiple accounts to be authenticated concurrently
/// so that integrations are able to operate on multiple accounts
/// provided they are authenticated.
pub struct AccountSwitcher<A, R, E>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    E: From<crate::Error> + std::error::Error + std::fmt::Debug,
{
    #[doc(hidden)]
    pub accounts: Vec<A>,
    selected: Option<Address>,
    paths: Option<Paths>,
    #[cfg(feature = "clipboard")]
    clipboard: Option<xclipboard::Clipboard>,
}

impl<A, R, E> AccountSwitcher<A, R, E>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    E: From<crate::Error> + std::error::Error + std::fmt::Debug,
{
    /// Create an account switcher.
    pub fn new() -> Self {
        Self {
            accounts: Default::default(),
            selected: None,
            paths: None,
            #[cfg(feature = "clipboard")]
            clipboard: None,
        }
    }

    /// Create an account switcher with a data directory.
    pub fn new_with_options(options: AccountSwitcherOptions) -> Self {
        Self {
            accounts: Default::default(),
            selected: None,
            paths: options.paths,
            #[cfg(feature = "clipboard")]
            clipboard: options.clipboard,
        }
    }

    /// Data directory.
    pub fn paths(&self) -> Option<&Paths> {
        self.paths.as_ref()
    }

    /// Accounts iterator.
    pub fn iter<'a>(&'a self) -> std::slice::Iter<'a, A> {
        self.accounts.iter()
    }

    /// Mutable accounts iterator.
    pub fn iter_mut<'a>(&'a mut self) -> std::slice::IterMut<'a, A> {
        self.accounts.iter_mut()
    }

    /// Number of accounts.
    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    /// Load accounts from disc and add them.
    pub async fn load_accounts<B>(
        &mut self,
        builder: B,
        paths: Option<PathBuf>,
    ) -> Result<()>
    where
        B: Fn(
            PublicIdentity,
        )
            -> Pin<Box<dyn Future<Output = std::result::Result<A, E>>>>,
    {
        Paths::scaffold(paths.clone()).await?;

        let identities = Identity::list_accounts(self.paths()).await?;

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

    /// Search all authenticated accounts.
    pub async fn search(
        &self,
        needle: String,
        filter: QueryFilter,
    ) -> std::result::Result<HashMap<Address, Vec<Document>>, E> {
        let mut out = HashMap::new();
        for account in self.iter() {
            if account.is_authenticated().await {
                let results =
                    account.query_map(&needle, filter.clone()).await?;
                out.insert(*account.address(), results);
            }
        }
        Ok(out)
    }

    /// Query a search index view for all authenticated accounts.
    pub async fn query_view(
        &self,
        views: &[DocumentView],
        archive_filter: Option<&ArchiveFilter>,
    ) -> std::result::Result<HashMap<Address, Vec<Document>>, E> {
        let mut out = HashMap::new();
        for account in self.iter() {
            if account.is_authenticated().await {
                let results =
                    account.query_view(views, archive_filter).await?;
                out.insert(*account.address(), results);
            }
        }
        Ok(out)
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

    /// Copy a secret to the clipboard.
    #[cfg(feature = "clipboard")]
    pub async fn copy_clipboard(
        &self,
        account_id: &Address,
        target: SecretPath,
    ) -> std::result::Result<bool, E> {
        let Some(clipboard) = self.clipboard.clone() else {
            return Ok(false);
        };

        let account = self.iter().find(|a| a.address() == account_id);
        if let Some(account) = account {
            let target_folder =
                account.find(|f| f.id() == target.folder_id()).await;
            if let Some(folder) = target_folder {
                let current_folder = account.current_folder().await?;
                let (data, _) = account
                    .read_secret(target.secret_id(), Some(folder))
                    .await?;
                if let Some(current) = &current_folder {
                    account.open_folder(current).await?;
                }
                let secret = data.secret();
                let text = secret.copy_value_unsafe().unwrap_or_default();
                clipboard
                    .set_text_timeout(text)
                    .await
                    .map_err(crate::Error::from)?;
                return Ok(false);
            }
        }

        Ok(false)
    }

    fn position(&self, address: &Address) -> Option<usize> {
        self.accounts.iter().position(|a| a.address() == address)
    }
}

impl<A, R, E> From<Paths> for AccountSwitcher<A, R, E>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    E: From<crate::Error> + std::error::Error + std::fmt::Debug,
{
    fn from(paths: Paths) -> Self {
        Self::new_with_options(AccountSwitcherOptions {
            paths: Some(paths),
            ..Default::default()
        })
    }
}
