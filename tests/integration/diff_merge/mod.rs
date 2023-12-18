use anyhow::Result;
use copy_dir::copy_dir;
use std::path::Path;

mod folder_create;
mod folder_delete;
mod folder_import;
mod folder_rename;

mod secret_create;
mod secret_update;
mod secret_delete;

pub fn copy_account(
    source: impl AsRef<Path>,
    target: impl AsRef<Path>,
) -> Result<()> {
    std::fs::remove_dir(target.as_ref())?;
    copy_dir(source.as_ref(), target.as_ref())?;
    Ok(())
}
