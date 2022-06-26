//! Iterate a WAL provider and reduce all the events
//! so that a single vault can be built.
//!
//! Uses a simple last event wins strategy.
//!
use std::{borrow::Cow, collections::HashMap};

use crate::{
    crypto::AeadPack,
    secret::SecretId,
    vault::{SecretGroup, Vault},
    Result,
};

/// Reducer for WAL events.
#[derive(Default)]
pub struct WalReducer<'a> {
    /// Buffer for the last create or update vault event.
    vault: Option<Cow<'a, [u8]>>,

    /// Last encountered vault name.
    vault_name: Option<Cow<'a, str>>,

    /// Last encountered vault meta data.
    vault_meta: Option<AeadPack>,

    /// Map of the reduced secrets.
    secrets: HashMap<SecretId, SecretGroup>,
}

impl<'a> WalReducer<'a> {
    /// Create a new reducer.
    pub fn new() -> Self {
        Default::default()
    }

    /// Reduce the events in the given iterator.
    pub fn reduce(self) -> Result<Self> {
        Ok(self)
    }

    /// Consume this reducer and build a vault.
    pub fn build(self) -> Result<Vault> {
        Ok(Default::default())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;

    #[test]
    fn wal_reduce_events() -> Result<()> {
        let vault = WalReducer::new().reduce()?.build()?;
        Ok(())
    }
}
