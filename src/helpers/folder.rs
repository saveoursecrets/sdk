use sos_core::vault::{Summary, VaultRef};

use crate::{
    helpers::account::{Owner, USER},
    Error, Result,
};

pub async fn resolve_folder(
    owner: &Owner,
    folder: Option<VaultRef>,
) -> Result<Option<Summary>> {
    let reader = owner.read().await;
    if let Some(vault) = folder {
        Ok(Some(
            reader
                .storage
                .state()
                .find_vault(&vault)
                .cloned()
                .ok_or(Error::VaultNotAvailable(vault))?,
        ))
    } else if let Some(owner) = USER.get() {
        let reader = owner.read().await;
        let keeper =
            reader.storage.current().ok_or(Error::NoVaultSelected)?;
        Ok(Some(keeper.summary().clone()))
    } else {
        Ok(reader.storage.state().find_default_vault().cloned())
    }
}
