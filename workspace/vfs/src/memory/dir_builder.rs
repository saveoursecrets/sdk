use std::io::{self, ErrorKind, Result};
use std::{
    ffi::OsString,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use super::fs::{
    has_parent, resolve, resolve_parent, root_fs_mut, MemoryFd, Parent,
    PathTarget,
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
        if self.recursive {
            let mut current = Parent::Root(root_fs_mut());
            let mut buf = PathBuf::new();
            let mut file_name: Option<OsString> = None;
            for component in path.as_ref().components() {
                match component {
                    Component::RootDir => {
                        continue;
                    }
                    Component::Normal(name) => {
                        buf = buf.join(name);
                        file_name = Some(name.to_owned());
                    }
                    _ => unimplemented!(),
                }

                // Got a directory to make
                if let Some(file_name) = file_name {
                    // See if a folder already exists at the location
                    if let Some(target) = resolve(&buf).await {
                        match target {
                            PathTarget::Descriptor(parent) => {
                                let fd = parent.read().await;
                                match &*fd {
                                    MemoryFd::Dir(_dir) => {
                                        current = Parent::Folder(Arc::clone(
                                            &parent,
                                        ));
                                    }
                                    _ => {
                                        return Err(
                                            ErrorKind::PermissionDenied
                                                .into(),
                                        )
                                    }
                                }
                            }
                            PathTarget::Root(_) => {
                                return Err(ErrorKind::PermissionDenied.into())
                            }
                        }
                    } else {
                        let fd = current.mkdir(file_name).await?;
                        current = Parent::Folder(fd);
                    }
                }
            }
            Ok(())
        } else {
            let file_name = path.as_ref().file_name().ok_or_else(|| {
                let err: io::Error = ErrorKind::PermissionDenied.into();
                err
            })?;

            let has_parent = has_parent(path.as_ref());
            if has_parent {
                if let Some(target) = resolve_parent(path.as_ref()).await {
                    match target {
                        PathTarget::Descriptor(parent) => {
                            let is_dir = {
                                let fd = parent.read().await;
                                matches!(&*fd, MemoryFd::Dir(_))
                            };
                            if is_dir {
                                Parent::Folder(parent)
                                    .mkdir(file_name.to_owned())
                                    .await?;
                            } else {
                                return Err(
                                    ErrorKind::PermissionDenied.into()
                                );
                            }
                        }
                        PathTarget::Root(fs) => {
                            Parent::Root(fs)
                                .mkdir(file_name.to_owned())
                                .await?;
                        }
                    }
                    Ok(())
                } else {
                    Err(ErrorKind::NotFound.into())
                }
            } else {
                Parent::Root(root_fs_mut())
                    .mkdir(file_name.to_owned())
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
