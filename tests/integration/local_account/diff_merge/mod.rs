use anyhow::Result;
use copy_dir::copy_dir;
use std::path::Path;

mod create_folder;

pub fn copy_account(
    source: impl AsRef<Path>,
    target: impl AsRef<Path>,
) -> Result<()> {
    std::fs::remove_dir(target.as_ref())?;
    copy_dir(source.as_ref(), target.as_ref())?;
    Ok(())
}
