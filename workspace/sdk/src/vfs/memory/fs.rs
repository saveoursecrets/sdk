//! File system backed by in-memory buffers.

use async_recursion::async_recursion;
use bitflags::bitflags;
use once_cell::sync::Lazy;
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    io::{self, Error, ErrorKind},
    iter::Enumerate,
    path::{Component, Components, Path, PathBuf},
    sync::Arc,
    vec::IntoIter,
};
use tokio::sync::{Mutex, RwLock};

use super::{Metadata, Permissions, Result};

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use super::meta_data::FileTime;

bitflags! {
    /// Bit flags for a file descriptor.
    #[derive(Default)]
    pub(crate) struct FileFlags: u8 {
        /// Descriptor is a directory.
        const DIR               =        0b00000001;
        /// Descriptor is a file.
        const FILE              =        0b00000010;
        /// Descriptor is a symbolic link.
        const SYM_LINK          =        0b00000100;
    }
}

type Fd = Arc<RwLock<MemoryFd>>;
type FileSystem = BTreeMap<OsString, Fd>;

// File system contents.
static mut FILE_SYSTEM: Lazy<MemoryDir> = Lazy::new(|| MemoryDir::new_root());

// Lock for when we need to modify the file system by adding
// or removing paths.
static FS_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

#[async_recursion]
async fn walk(
    target: &MemoryDir,
    it: &mut Enumerate<IntoIter<Component>>,
    length: usize,
    parents: &mut Vec<Fd>,
) -> Option<Fd> {
    if let Some((index, part)) = it.next() {
        match part {
            Component::RootDir => {
                if target.is_root() {
                    if let Some((index, part)) = it.next() {
                        match part {
                            Component::Normal(name) => {
                                if index == length - 1 {
                                    return target
                                        .files
                                        .get(name)
                                        .map(Arc::clone);
                                } else {
                                    if let Some(child) =
                                        target.find_dir(name).await
                                    {
                                        parents.push(Arc::clone(&child));
                                        let fd = child.read().await;
                                        if let MemoryFd::Dir(dir) = &*fd {
                                            return walk(
                                                dir, it, length, parents,
                                            )
                                            .await;
                                        }
                                    } else {
                                        return None;
                                    }
                                }
                            }
                            _ => {}
                        }
                    } else {
                        return None;
                    }
                } else {
                    return None;
                }
            }
            Component::Normal(name) => {
                if index == length - 1 {
                    return target.files.get(name).map(Arc::clone);
                } else {
                    if let Some(child) = target.find_dir(name).await {
                        parents.push(Arc::clone(&child));
                        let fd = child.read().await;
                        if let MemoryFd::Dir(dir) = &*fd {
                            return walk(dir, it, length, parents).await;
                        }
                    } else {
                        return None;
                    }
                }
            }
            _ => return None,
        }
    }
    None
}

pub(super) async fn resolve_relative(
    fs: &MemoryDir,
    path: impl AsRef<Path>,
) -> Option<Arc<RwLock<MemoryFd>>> {
    let components: Vec<Component> =
        path.as_ref().components().into_iter().collect();
    let length = components.len();
    let mut it = components.into_iter().enumerate();
    walk(fs, &mut it, length, &mut vec![]).await
}

fn root_fs() -> &'static MemoryDir {
    unsafe { &FILE_SYSTEM }
}

fn root_fs_mut() -> &'static mut MemoryDir {
    unsafe { &mut FILE_SYSTEM }
}

pub(super) async fn resolve(
    path: impl AsRef<Path>,
) -> Option<Arc<RwLock<MemoryFd>>> {
    unsafe {
        let fs = root_fs();
        resolve_relative(&*fs, path).await
    }
}

pub(super) async fn resolve_parent(
    path: impl AsRef<Path>,
) -> Option<Arc<RwLock<MemoryFd>>> {
    if let Some(parent) = path.as_ref().parent() {
        resolve(parent).await
    } else {
        None
    }
}

/// Directory reference.
#[derive(Default, Debug, Clone)]
pub(super) struct MemoryDir {
    parent: Option<Fd>,
    permissions: Permissions,
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    time: FileTime,
    files: FileSystem,
}

impl MemoryDir {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    fn new_root() -> Self {
        Self {
            parent: None,
            permissions: Default::default(),
            time: Default::default(),
            files: Default::default(),
        }
    }

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    fn new_root() -> Self {
        Self {
            parent: None,
            permissions: Default::default(),
            files: Default::default(),
        }
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    fn new_parent(parent: Fd) -> Self {
        Self {
            parent: Some(parent),
            permissions: Default::default(),
            time: Default::default(),
            files: Default::default(),
        }
    }

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    fn new_parent(parent: Fd) -> Self {
        Self {
            parent: Some(parent),
            permissions: Default::default(),
            files: Default::default(),
        }
    }

    pub fn is_root(&self) -> bool {
        self.parent.is_none()
    }

    /// Determine if the file is empty.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Get the length.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    fn get(&self, name: &OsStr) -> Option<&Fd> {
        self.files.get(name)
    }

    fn insert(&mut self, name: OsString, fd: MemoryFd) {
        let child = Arc::new(RwLock::new(fd));
        self.insert_fd(name, child);
    }

    fn insert_fd(&mut self, name: OsString, fd: Fd) {
        self.files.insert(name, fd);
    }

    /// Find a child that is a dir.
    async fn find_dir(&self, name: &OsStr) -> Option<Fd> {
        if let Some(child) = self.files.get(name) {
            let is_dir = {
                let fd = child.read().await;
                matches!(&*fd, MemoryFd::Dir(_))
            };
            if is_dir {
                Some(Arc::clone(child))
            } else {
                None
            }
        } else {
            None
        }
    }
}

fn mkdir(target: &mut MemoryDir, parent: Fd, name: OsString) {
    let child = MemoryFd::Dir(MemoryDir::new_parent(parent));
    target.insert(name, child);
}

/// Create a new file.
///
/// The parent directory must exist.
pub(super) async fn create_file(
    path: impl AsRef<Path>,
    contents: Vec<u8>,
    truncate: bool,
) -> Result<Fd> {
    let file_name = path.as_ref().file_name().ok_or_else(|| {
        let err: io::Error = ErrorKind::PermissionDenied.into();
        err
    })?;

    // File already exists
    if let Some(file) = resolve(path.as_ref()).await {
        let mut file_fd = file.write().await;
        if let Some(parent) = file_fd.parent() {
            match &mut *file_fd {
                MemoryFd::Dir(_) => Err(ErrorKind::PermissionDenied.into()),
                MemoryFd::File(fd) => {
                    if truncate {
                        fd.contents = Vec::new();
                    }
                    Ok(Arc::clone(&file))
                }
            }
        } else {
            Err(ErrorKind::PermissionDenied.into())
        }
    // Try to create in parent
    } else {
        if let Some(parent) = resolve_parent(path.as_ref()).await {
            let mut parent_fd = parent.write().await;
            match &mut *parent_fd {
                MemoryFd::Dir(dir) => {
                    let new_file = MemoryFd::File(MemoryFile::new(
                        Arc::clone(&parent),
                        contents,
                    ));
                    dir.insert(file_name.to_owned(), new_file);
                    Ok(dir.get(file_name).map(Arc::clone).unwrap())
                }
                MemoryFd::File(_) => Err(ErrorKind::PermissionDenied.into()),
            }
        // Create at the root
        } else {
            let dir = root_fs_mut();
            let new_file = MemoryFd::File(MemoryFile::new(
                Arc::new(RwLock::new(MemoryFd::Dir(dir.clone()))),
                contents,
            ));
            dir.insert(file_name.to_owned(), new_file);
            Ok(dir.get(file_name).map(Arc::clone).unwrap())
        }
    }
}

/// File content.
#[derive(Debug)]
pub(super) struct MemoryFile {
    parent: Fd,
    permissions: Permissions,
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    time: FileTime,
    pub(super) contents: Vec<u8>,
}

impl MemoryFile {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    fn new(parent: Fd, contents: Vec<u8>) -> Self {
        Self {
            parent,
            permissions: Default::default(),
            time: Default::default(),
            contents,
        }
    }

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    fn new(parent: Fd, contents: Vec<u8>) -> Self {
        Self {
            parent,
            permissions: Default::default(),
            contents,
        }
    }

    /// Determine if the file is empty.
    pub fn is_empty(&self) -> bool {
        self.contents.is_empty()
    }

    /// Get the length of the file buffer.
    pub fn len(&self) -> usize {
        self.contents.len()
    }
}

/// File descriptor.
#[derive(Debug)]
pub(super) enum MemoryFd {
    /// File variant.
    File(MemoryFile),
    /// Directory variant.
    Dir(MemoryDir),
}

impl MemoryFd {
    /// Determine if the file is empty or a directory
    /// has no contents.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::File(fd) => fd.is_empty(),
            Self::Dir(fd) => fd.is_empty(),
        }
    }

    /// Get the length of a file in bytes or the number
    /// of entries in a directory.
    pub fn len(&self) -> usize {
        match self {
            Self::File(fd) => fd.len(),
            Self::Dir(fd) => fd.len(),
        }
    }

    /// Remove a child file or directory.
    ///
    /// # Panics
    ///
    /// If this file descriptor is not a directory.
    pub(crate) fn unlink(&mut self, path: impl AsRef<Path>) -> Option<Fd> {
        match self {
            Self::Dir(fd) => {
                if let Some(name) = path.as_ref().file_name() {
                    fd.files.remove(name)
                } else {
                    None
                }
            }
            Self::File(fd) => unreachable!(),
        }
    }

    pub(crate) fn parent(&self) -> Option<Fd> {
        match self {
            Self::File(fd) => Some(Arc::clone(&fd.parent)),
            Self::Dir(fd) => fd.parent.as_ref().map(Arc::clone),
        }
    }

    pub(crate) fn flags(&self) -> FileFlags {
        match self {
            Self::File(_) => FileFlags::FILE,
            Self::Dir(_) => FileFlags::DIR,
        }
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub(crate) fn time(&self) -> &FileTime {
        match self {
            Self::File(fd) => &fd.time,
            Self::Dir(fd) => &fd.time,
        }
    }

    pub(crate) fn set_permissions(&mut self, perm: Permissions) {
        match self {
            Self::File(fd) => fd.permissions = perm,
            Self::Dir(fd) => fd.permissions = perm,
        }
    }

    pub(crate) fn permissions(&self) -> &Permissions {
        match self {
            Self::File(fd) => &fd.permissions,
            Self::Dir(fd) => &fd.permissions,
        }
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub(crate) fn metadata(&self) -> Metadata {
        Metadata::new(
            self.permissions().clone(),
            self.flags(),
            self.len() as u64,
            self.time().clone(),
        )
    }

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    pub(crate) fn metadata(&self) -> Metadata {
        Metadata::new(
            self.permissions().clone(),
            self.flags(),
            self.len() as u64,
        )
    }
}

/// Ensure a path is a file and exists.
async fn ensure_file(path: impl AsRef<Path>) -> Result<Fd> {
    let fd = resolve(path.as_ref().to_path_buf()).await;
    if let Some(file) = fd {
        let is_file = {
            let fd = file.read().await;
            matches!(&*fd, MemoryFd::File(_))
        };
        if is_file {
            Ok(file)
        } else {
            Err(ErrorKind::PermissionDenied.into())
        }
    } else {
        Err(ErrorKind::NotFound.into())
    }
}

/// Ensure a path is a directory and exists.
async fn ensure_dir(path: impl AsRef<Path>) -> Result<Fd> {
    if let Some(file) = resolve(path.as_ref().to_path_buf()).await {
        let is_dir = {
            let fd = file.read().await;
            matches!(&*fd, MemoryFd::Dir(_))
        };
        if is_dir {
            Ok(file)
        } else {
            Err(ErrorKind::PermissionDenied.into())
        }
    } else {
        Err(ErrorKind::NotFound.into())
    }
}

fn has_parent(path: impl AsRef<Path>) -> bool {
    if let Some(parent) = path.as_ref().parent() {
        !parent.as_os_str().is_empty()
    } else {
        false
    }
}

/// Creates a future that will open a file for writing
/// and write the entire contents to it.
pub async fn write(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
) -> Result<()> {
    if let Some(file) = resolve(path.as_ref()).await {
        let mut fd = file.write().await;
        match &mut *fd {
            MemoryFd::File(fd) => {
                fd.contents = contents.as_ref().to_vec();
                Ok(())
            }
            MemoryFd::Dir(_) => Err(ErrorKind::PermissionDenied.into()),
        }
    } else {
        let has_parent = has_parent(path.as_ref());
        if has_parent {
            if let Some(parent) = resolve_parent(path.as_ref()).await {
                let fd = parent.read().await;
                match &*fd {
                    MemoryFd::Dir(_) => {
                        create_file(path, contents.as_ref().to_vec(), false)
                            .await?;
                        Ok(())
                    }
                    MemoryFd::File(_) => {
                        Err(ErrorKind::PermissionDenied.into())
                    }
                }
            } else {
                Err(ErrorKind::NotFound.into())
            }
        } else {
            create_file(path, contents.as_ref().to_vec(), false).await?;
            Ok(())
        }
    }
}

/// Reads the entire contents of a file into a bytes vector.
pub async fn read(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    if let Some(fd) = resolve(path.as_ref().to_path_buf()).await {
        let fd = fd.read().await;
        if let MemoryFd::File(fd) = &*fd {
            Ok(fd.contents.clone())
        } else {
            Err(ErrorKind::PermissionDenied.into())
        }
    } else {
        Err(ErrorKind::NotFound.into())
    }
}

/// Removes a file from the filesystem.
pub async fn remove_file(path: impl AsRef<Path>) -> Result<()> {
    let _ = FS_LOCK.lock().await;

    let file = ensure_file(path.as_ref()).await?;
    let fd = file.write().await;
    if let Some(parent) = fd.parent().take() {
        let mut parent_fd = parent.write().await;
        parent_fd.unlink(path);
    }
    Ok(())
}

/// Removes an existing, empty directory.
pub async fn remove_dir(path: impl AsRef<Path>) -> Result<()> {
    let _ = FS_LOCK.lock().await;

    let dir = ensure_dir(path.as_ref()).await?;
    let fd = dir.write().await;
    if fd.is_empty() {
        if let Some(parent) = fd.parent().take() {
            let mut parent_fd = parent.write().await;
            parent_fd.unlink(path);
        }
        Ok(())
    } else {
        Err(ErrorKind::PermissionDenied.into())
    }
}

/// Removes a directory at this path, after removing
/// all its contents. Use carefully!
pub async fn remove_dir_all(path: impl AsRef<Path>) -> Result<()> {
    let _ = FS_LOCK.lock().await;

    let dir = ensure_dir(path.as_ref()).await?;
    let fd = dir.write().await;
    if let Some(parent) = fd.parent().take() {
        let mut parent_fd = parent.write().await;
        parent_fd.unlink(path);
    }
    Ok(())
}

/// Renames a file or directory to a new name, replacing
/// the original file if to already exists.
pub async fn rename(
    from: impl AsRef<Path>,
    to: impl AsRef<Path>,
) -> Result<()> {
    let _ = FS_LOCK.lock().await;

    let file = resolve(from.as_ref()).await.ok_or_else(|| {
        let err: io::Error = ErrorKind::NotFound.into();
        err
    })?;

    let mut fd = file.write().await;

    let parent = fd.parent().ok_or_else(|| {
        let err: io::Error = ErrorKind::PermissionDenied.into();
        err
    })?;

    let from_name = from.as_ref().file_name().ok_or_else(|| {
        let err: io::Error = ErrorKind::PermissionDenied.into();
        err
    })?;

    let to_name = to.as_ref().file_name().ok_or_else(|| {
        let err: io::Error = ErrorKind::PermissionDenied.into();
        err
    })?;

    let mut parent_fd = parent.write().await;
    if let Some(source) = parent_fd.unlink(from_name) {
        if let Some(to_file) = resolve(to.as_ref()).await {
            let to_fd = to_file.write().await;
            // Overwrite existing file
            if matches!(&*to_fd, MemoryFd::File(_)) {
                if let Some(to_parent_fd) = to_fd.parent() {
                    let mut to_parent_write = to_parent_fd.write().await;
                    match &mut *to_parent_write {
                        MemoryFd::Dir(dir) => {
                            dir.insert_fd(to_name.to_owned(), source);
                        }
                        _ => unreachable!(),
                    }
                }
                Ok(())
            // Cannot overwrite a directory
            } else {
                Err(ErrorKind::PermissionDenied.into())
            }
        } else {
            // To does not exist but it's parent must
            if let Some(to_parent_fd) = resolve_parent(to.as_ref()).await {
                let mut to_parent_write = to_parent_fd.write().await;
                match &mut *to_parent_write {
                    MemoryFd::Dir(dir) => {
                        dir.insert_fd(to_name.to_owned(), source);
                    }
                    _ => unreachable!(),
                }

                Ok(())
            } else {
                Err(ErrorKind::NotFound.into())
            }
        }
    } else {
        Err(ErrorKind::NotFound.into())
    }
}

/// Creates a new, empty directory at the provided path.
pub async fn create_dir(path: impl AsRef<Path>) -> Result<()> {
    let _ = FS_LOCK.lock().await;

    if let Some(parent) = resolve_parent(path.as_ref()).await {
        let mut fd = parent.write().await;
        match &mut *fd {
            MemoryFd::Dir(dir) => {
                if let Some(name) = path.as_ref().file_name() {
                    mkdir(dir, Arc::clone(&parent), name.to_owned());
                    Ok(())
                } else {
                    // TODO: different error here?
                    Err(ErrorKind::PermissionDenied.into())
                }
            }
            _ => Err(ErrorKind::PermissionDenied.into()),
        }
    } else {
        Err(ErrorKind::NotFound.into())
    }
}

/// Recursively creates a directory and all of its parent
/// components if they are missing.
pub async fn create_dir_all(path: impl AsRef<Path>) -> Result<()> {
    let _ = FS_LOCK.lock().await;

    let mut it = path.as_ref().iter();
    let mut path = if path.as_ref().is_absolute() {
        it.next().map(PathBuf::from).unwrap_or_default()
    } else {
        PathBuf::new()
    };

    unsafe {
        let mut target = root_fs_mut();
        for part in it {
            path = path.join(part);
            if let Some(child) = resolve(&path).await {
                let mut fd = child.write().await;
                match &mut *fd {
                    MemoryFd::Dir(dir) => {
                        target = dir;
                        continue;
                    }
                    _ => return Err(ErrorKind::PermissionDenied.into()),
                }
            } else {
                create_dir(&path).await?;
            }
        }
    }

    Ok(())
}

/// Creates a future which will open a file for reading
/// and read the entire contents into a string and return said string.
pub async fn read_to_string(path: impl AsRef<Path>) -> Result<String> {
    let contents = read(path).await?;
    Ok(String::from_utf8(contents).map_err(|_| {
        let err: Error = ErrorKind::InvalidData.into();
        err
    })?)
}

/// Given a path, queries the file system to get information about a file, directory, etc.
pub async fn metadata(path: impl AsRef<Path>) -> io::Result<Metadata> {
    if let Some(fd) = resolve(path.as_ref().to_path_buf()).await {
        let fd = fd.read().await;
        Ok(fd.metadata())
    } else {
        Err(ErrorKind::NotFound.into())
    }
}

/// Changes the permissions found on a file or a directory.
pub async fn set_permissions(
    path: impl AsRef<Path>,
    perm: Permissions,
) -> Result<()> {
    if let Some(fd) = resolve(path.as_ref()).await {
        let mut fd = fd.write().await;
        fd.set_permissions(perm);
        Ok(())
    } else {
        Err(ErrorKind::NotFound.into())
    }
}
