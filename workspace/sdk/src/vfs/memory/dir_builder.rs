use std::io::{self, ErrorKind, Result};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    sync::Arc,
};

use super::fs::{
    has_parent, resolve, resolve_parent, root_fs_mut, Fd, MemoryDir,
    MemoryFd, Parent, FS_LOCK,
};

/// A builder for creating directories in various manners.
#[derive(Debug, Default)]
pub struct DirBuilder {
    /// Indicates whether to create parent directories
    /// if they are missing.
    recursive: bool,
}

impl DirBuilder {
    /// Creates a new set of options with default
    /// mode/security settings for all platforms and also non-recursive.
    pub fn new() -> Self {
        Default::default()
    }

    /// Indicates whether to create directories
    /// recursively (including all parent directories).
    /// Parents that do not exist are created with the
    /// same security and permissions settings.
    ///
    /// This option defaults to `false`.
    pub fn recursive(&mut self, recursive: bool) -> &mut Self {
        self.recursive = recursive;
        self
    }

    /// Creates the specified directory with the configured options.
    ///
    /// It is considered an error if the directory already exists unless
    /// recursive mode is enabled.
    ///
    /// # Errors
    ///
    /// An error will be returned under the following circumstances:
    ///
    /// * Path already points to an existing file.
    /// * Path already points to an existing directory and the mode is
    ///   non-recursive.
    /// * The calling process doesn't have permissions to create the directory
    ///   or its missing parents.
    /// * Other I/O error occurred.
    pub async fn create(&self, path: impl AsRef<Path>) -> Result<()> {
        let _ = FS_LOCK.lock().await;

        if self.recursive {
            let mut it = path.as_ref().iter();
            let mut path = if path.as_ref().is_absolute() {
                it.next().map(PathBuf::from).unwrap_or_default()
            } else {
                PathBuf::new()
            };

            /*
            let mut target = new_root_parent();
            for name in it {
                path = path.join(name);
                if let Some(child) = resolve(&path).await {
                    let mut fd = child.write().await;
                    match &mut *fd {
                        MemoryFd::Dir(dir) => {
                            target = Arc::clone(&child);
                            continue;
                        }
                        _ => return Err(ErrorKind::PermissionDenied.into()),
                    }
                } else {
                    mkdir(Arc::clone(&target), name.to_owned()).await?;
                }
            }
            */

            todo!();

            Ok(())
        } else {
            let file_name = path.as_ref().file_name().ok_or_else(|| {
                let err: io::Error = ErrorKind::PermissionDenied.into();
                err
            })?;

            let has_parent = has_parent(path.as_ref());
            if has_parent {
                if let Some(parent) = resolve_parent(path.as_ref()).await {
                    /*
                    let mut fd = parent.write().await;
                    match &mut *fd {
                        MemoryFd::Dir(dir) => {
                            mkdir(Arc::clone(&parent), file_name.to_owned())
                                .await?;
                            Ok(())
                        }
                        _ => Err(ErrorKind::PermissionDenied.into()),
                    }
                    */

                    todo!();
                } else {
                    Err(ErrorKind::NotFound.into())
                }
            } else {
                mkdir(Parent::Root(root_fs_mut()), file_name.to_owned())
                    .await?;
                Ok(())
            }
        }
    }
}

/// Creates a new, empty directory at the provided path.
pub async fn create_dir(path: impl AsRef<Path>) -> Result<()> {
    DirBuilder::new().create(path).await
}

/// Recursively creates a directory and all of its parent
/// components if they are missing.
pub async fn create_dir_all(path: impl AsRef<Path>) -> Result<()> {
    DirBuilder::new().recursive(true).create(path).await
}

async fn mkdir(mut parent: Parent, name: OsString) -> Result<()> {
    parent.mkdir(name).await
}
