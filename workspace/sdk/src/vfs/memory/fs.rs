//! File system backed by in-memory buffers.

use async_recursion::async_recursion;
use bitflags::bitflags;
use once_cell::sync::Lazy;
use parking_lot::Mutex as SyncMutex;
use std::{
    borrow::Cow,
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    io::{self, Cursor, Error, ErrorKind},
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

pub(super) type Fd = Arc<RwLock<MemoryFd>>;
pub(super) type FileSystem = BTreeMap<OsString, Fd>;

// File system contents.
static mut FILE_SYSTEM: Lazy<MemoryDir> = Lazy::new(|| MemoryDir::new_root());

// Lock for when we need to modify the file system by adding
// or removing paths.
pub(super) static FS_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

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
                // Got a root request only
                if length == 1 {
                    return Some(Arc::new(RwLock::new(MemoryFd::Dir(
                        root_fs().clone(),
                    ))));
                }

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

pub(super) fn root_fs() -> &'static MemoryDir {
    unsafe { &FILE_SYSTEM }
}

pub(super) fn root_fs_mut() -> &'static mut MemoryDir {
    unsafe { &mut FILE_SYSTEM }
}

#[deprecated]
pub(super) fn new_root_parent() -> Fd {
    let dir = root_fs();
    Arc::new(RwLock::new(MemoryFd::Dir(dir.clone())))
}

pub(super) async fn resolve(
    path: impl AsRef<Path>,
) -> Option<Arc<RwLock<MemoryFd>>> {
    let fs = root_fs();
    resolve_relative(&*fs, path).await
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
    name: OsString,
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
            name: OsString::new(),
            parent: None,
            permissions: Default::default(),
            time: Default::default(),
            files: Default::default(),
        }
    }

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    fn new_root() -> Self {
        Self {
            name: OsString::new(),
            parent: None,
            permissions: Default::default(),
            files: Default::default(),
        }
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub(super) fn new_parent(name: OsString, parent: Option<Fd>) -> Self {
        Self {
            name,
            parent,
            permissions: Default::default(),
            time: Default::default(),
            files: Default::default(),
        }
    }

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    pub(super) fn new_parent(name: OsString, parent: Option<Fd>) -> Self {
        Self {
            name,
            parent,
            permissions: Default::default(),
            files: Default::default(),
        }
    }

    pub fn files(&self) -> &FileSystem {
        &self.files
    }

    pub fn is_root(&self) -> bool {
        self.parent.is_none()
    }

    pub fn get(&self, name: &OsStr) -> Option<&Fd> {
        self.files.get(name)
    }

    pub fn insert(&mut self, name: OsString, fd: MemoryFd) {
        let child = Arc::new(RwLock::new(fd));
        self.insert_fd(name, child);
    }

    pub fn insert_fd(&mut self, name: OsString, fd: Fd) {
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
                        fd.truncate();
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
                        file_name.to_owned(),
                        Some(Arc::clone(&parent)),
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
                file_name.to_owned(),
                // NOTE: must not give a parent here
                None,
                contents,
            ));
            dir.insert(file_name.to_owned(), new_file);
            Ok(dir.get(file_name).map(Arc::clone).unwrap())
        }
    }
}

/// File content.
#[derive(Debug, Clone)]
pub(super) struct MemoryFile {
    name: OsString,
    parent: Option<Fd>,
    permissions: Permissions,
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    time: FileTime,
    pub(super) contents: Arc<SyncMutex<Cursor<Vec<u8>>>>,
}

impl MemoryFile {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    fn new(name: OsString, parent: Option<Fd>, contents: Vec<u8>) -> Self {
        Self {
            name,
            parent,
            permissions: Default::default(),
            time: Default::default(),
            contents: Arc::new(SyncMutex::new(Cursor::new(contents))),
        }
    }

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    fn new(name: OsString, parent: Option<Fd>, contents: Vec<u8>) -> Self {
        Self {
            name,
            parent,
            permissions: Default::default(),
            contents: Arc::new(SyncMutex::new(Cursor::new(contents))),
        }
    }

    pub fn truncate(&self) {
        let mut lock = self.contents.lock();
        *lock = Cursor::new(Vec::new());
    }

    pub fn contents(&self) -> Arc<SyncMutex<Cursor<Vec<u8>>>> {
        Arc::clone(&self.contents)
    }
}

/// File descriptor.
#[derive(Debug, Clone)]
pub(super) enum MemoryFd {
    /// File variant.
    File(MemoryFile),
    /// Directory variant.
    Dir(MemoryDir),
}

impl MemoryFd {
    /// Remove a child file or directory.
    ///
    /// # Panics
    ///
    /// If this file descriptor is not a directory.
    pub fn unlink(&mut self, path: impl AsRef<Path>) -> Option<Fd> {
        match self {
            Self::Dir(dir) => {
                if let Some(name) = path.as_ref().file_name() {
                    log::info!("{:#?}", dir.files());
                    log::info!("REMOVING THE CHILD {:#?} {:#?}", name, dir.get(name));
                    dir.files.remove(name)
                } else {
                    None
                }
            }
            Self::File(fd) => unreachable!(),
        }
    }

    pub fn parent(&self) -> Option<Fd> {
        match self {
            Self::File(fd) => {
                Some(fd.parent.as_ref().map(Arc::clone)
                    .unwrap_or_else(|| Arc::new(
                        RwLock::new(MemoryFd::Dir(root_fs().clone())))))
            },
            Self::Dir(fd) => {
                if fd.is_root() {
                    None
                } else {
                    Some(fd.parent.as_ref().map(Arc::clone)
                        .unwrap_or_else(|| Arc::new(
                            RwLock::new(MemoryFd::Dir(root_fs().clone())))))
                }
            },
        }
    }

    pub fn name(&self) -> &OsString {
        match self {
            Self::File(fd) => &fd.name,
            Self::Dir(fd) => &fd.name,
        }
    }

    pub async fn path(&self) -> PathBuf {
        let mut parent = self.parent();
        let mut components = vec![self.name().clone()];
        while let Some(fd) = parent {
            let fd = fd.read().await;
            components.push(fd.name().clone());
            parent = fd.parent();
        }
        components.reverse();
        let mut path = PathBuf::new();
        for part in components {
            path = path.join(part);
        }
        path
    }

    pub fn flags(&self) -> FileFlags {
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

    pub fn set_permissions(&mut self, perm: Permissions) {
        match self {
            Self::File(fd) => fd.permissions = perm,
            Self::Dir(fd) => fd.permissions = perm,
        }
    }

    pub fn permissions(&self) -> &Permissions {
        match self {
            Self::File(fd) => &fd.permissions,
            Self::Dir(fd) => &fd.permissions,
        }
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

pub(super) fn has_parent(path: impl AsRef<Path>) -> bool {
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
                let buf = fd.contents();
                let mut data = buf.lock();
                *data = Cursor::new(contents.as_ref().to_vec());
                Ok(())
            }
            MemoryFd::Dir(_) => Err(ErrorKind::PermissionDenied.into()),
        }
    } else {
        let has_parent = has_parent(path.as_ref());
        if has_parent {
            if let Some(parent) = resolve_parent(path.as_ref()).await {
                let is_dir = {
                    let fd = parent.read().await;
                    matches!(&*fd, MemoryFd::Dir(_))
                };
                if is_dir {
                    create_file(path, contents.as_ref().to_vec(), false)
                        .await?;
                    Ok(())
                } else {
                    Err(ErrorKind::PermissionDenied.into())
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
            let buf = fd.contents();
            let data = buf.lock();
            Ok((&*data).clone().into_inner())
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
        log::info!("calling unlink on {} in {:#?}",
            path.as_ref().display(), parent_fd.name());
        parent_fd.unlink(path);

        log::info!("after remove {:#?}", root_fs().files().len());
    }
    Ok(())
}

/// Removes an existing, empty directory.
pub async fn remove_dir(path: impl AsRef<Path>) -> Result<()> {
    let _ = FS_LOCK.lock().await;

    let dir = ensure_dir(path.as_ref()).await?;
    let fd = dir.write().await;
    match &*fd {
        MemoryFd::Dir(dir) => {
            if dir.files().is_empty() {
                if let Some(parent) = fd.parent().take() {
                    let mut parent_fd = parent.write().await;
                    parent_fd.unlink(path);
                }
                Ok(())
            } else {
                Err(ErrorKind::PermissionDenied.into())
            }
        }
        _ => Err(ErrorKind::PermissionDenied.into()),
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
        let len = {
            let fd = fd.read().await;
            match &*fd {
                MemoryFd::File(file) => {
                    let data = file.contents();
                    let data = data.lock();
                    (&*data).get_ref().len() as u64
                }
                _ => 0u64,
            }
        };
        Ok(new_metadata(fd, len).await)
    } else {
        Err(ErrorKind::NotFound.into())
    }
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
async fn new_metadata(fd: Fd, len: u64) -> Metadata {
    let fd = fd.read().await;
    Metadata::new(
        fd.permissions().clone(),
        fd.flags(),
        len,
        fd.time().clone(),
    )
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
async fn new_metadata(fd: Fd, len: u64) -> Metadata {
    let fd = fd.read().await;
    Metadata::new(fd.permissions().clone(), fd.flags(), len)
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

/// Returns Ok(true) if the path points at an existing entity.
pub async fn try_exists(path: impl AsRef<Path>) -> Result<bool> {
    log::info!("try_exists {:#?}", path.as_ref());
    Ok(resolve(path).await.is_some())
}
