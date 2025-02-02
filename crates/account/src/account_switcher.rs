use crate::{Account, Error, LocalAccount, Result};
use sos_core::AccountId;
use sos_sdk::{prelude::PublicIdentity, Paths};
use sos_vault::list_accounts;
use std::path::PathBuf;
use std::pin::Pin;
use std::{collections::HashMap, future::Future};

#[cfg(feature = "search")]
use sos_search::{ArchiveFilter, Document, DocumentView, QueryFilter};

#[cfg(feature = "clipboard")]
use {crate::ClipboardCopyRequest, xclipboard::Clipboard};

#[cfg(feature = "clipboard")]
use sos_sdk::prelude::SecretPath;

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
    selected: Option<AccountId>,
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
        data_dir: Option<PathBuf>,
    ) -> Result<()>
    where
        B: Fn(
            PublicIdentity,
        )
            -> Pin<Box<dyn Future<Output = std::result::Result<A, E>>>>,
    {
        Paths::scaffold(data_dir.clone()).await?;

        let paths = if let Some(data_dir) = data_dir {
            Paths::new_global(data_dir)
        } else {
            Paths::new_global(Paths::data_dir()?)
        };

        let identities = list_accounts(Some(&paths)).await?;

        for identity in identities {
            tracing::info!(
                account_id = %identity.account_id(), "add_account");
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
        let account_id = *account.account_id();
        if self.add_account(account) {
            self.selected = Some(account_id);
            true
        } else {
            self.selected = Some(account_id);
            false
        }
    }

    /// Add an account to the collection if it does not already exist.
    pub fn add_account(&mut self, account: A) -> bool {
        if self.position(account.account_id()).is_none() {
            self.accounts.push(account);
            true
        } else {
            false
        }
    }

    /// Remove an account from the collection if it exists.
    pub fn remove_account(&mut self, account_id: &AccountId) -> bool {
        if let Some(position) = self.position(account_id) {
            self.accounts.remove(position);
            if self.selected == Some(*account_id) {
                self.selected = None;
            }
            true
        } else {
            false
        }
    }

    /// Switch selected account.
    ///
    /// If no account exists for the given account_id no change
    /// is made to the current selection.
    pub fn switch_account(&mut self, account_id: &AccountId) -> bool {
        if self.position(account_id).is_some() {
            self.selected = Some(*account_id);
            true
        } else {
            false
        }
    }

    /// Selected account.
    pub fn selected_account(&self) -> Option<&A> {
        if let Some(account_id) = &self.selected {
            if let Some(index) = self.position(account_id) {
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
        if let Some(account_id) = &self.selected {
            if let Some(index) = self.position(account_id) {
                self.accounts.get_mut(index)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Search all authenticated accounts.
    #[cfg(feature = "search")]
    pub async fn search(
        &self,
        needle: String,
        filter: QueryFilter,
    ) -> std::result::Result<HashMap<AccountId, Vec<Document>>, E> {
        let mut out = HashMap::new();
        for account in self.iter() {
            if account.is_authenticated().await {
                let results =
                    account.query_map(&needle, filter.clone()).await?;
                out.insert(*account.account_id(), results);
            }
        }
        Ok(out)
    }

    /// Query a search index view for all authenticated accounts.
    #[cfg(feature = "search")]
    pub async fn query_view(
        &self,
        views: &[DocumentView],
        archive_filter: Option<&ArchiveFilter>,
    ) -> std::result::Result<HashMap<AccountId, Vec<Document>>, E> {
        let mut out = HashMap::new();
        for account in self.iter() {
            if account.is_authenticated().await {
                let results =
                    account.query_view(views, archive_filter).await?;
                out.insert(*account.account_id(), results);
            }
        }
        Ok(out)
    }

    /// Sign out of all authenticated accounts.
    pub async fn sign_out_all(&mut self) -> std::result::Result<(), E> {
        for account in &mut self.accounts {
            if account.is_authenticated().await {
                tracing::info!(account = %account.account_id(), "sign out");
                account.sign_out().await?;
            }
        }
        Ok(())
    }

    /// Copy a secret to the clipboard.
    #[cfg(feature = "clipboard")]
    pub async fn copy_clipboard(
        &self,
        account_id: &AccountId,
        target: &SecretPath,
        request: &ClipboardCopyRequest,
    ) -> std::result::Result<bool, E> {
        let Some(clipboard) = self.clipboard.clone() else {
            return Err(Error::NoClipboard.into());
        };

        let account = self.iter().find(|a| a.account_id() == account_id);
        if let Some(account) = account {
            account.copy_clipboard(&clipboard, target, request).await
        } else {
            Ok(false)
        }
    }

    fn position(&self, account_id: &AccountId) -> Option<usize> {
        self.accounts
            .iter()
            .position(|a| a.account_id() == account_id)
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
