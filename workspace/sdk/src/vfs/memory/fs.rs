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
pub(super) type FileContent = Arc<SyncMutex<Cursor<Vec<u8>>>>;

// File system contents.
static mut FILE_SYSTEM: Lazy<MemoryDir> = Lazy::new(|| MemoryDir::new_root());

// Lock for when we need to modify the file system by adding
// or removing paths.
pub(super) static FS_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

pub(super) fn root_fs() -> &'static MemoryDir {
    unsafe { &FILE_SYSTEM }
}

pub(super) fn root_fs_mut() -> &'static mut MemoryDir {
    unsafe { &mut FILE_SYSTEM }
}

/// Result of a path lookup.
pub(super) enum PathTarget {
    Root(&'static mut MemoryDir),
    Descriptor(Fd),
}

/// Parent reference for a file descriptor.
#[derive(Debug)]
pub(super) enum Parent {
    Root(&'static mut MemoryDir),
    Folder(Fd),
}

impl Clone for Parent {
    fn clone(&self) -> Self {
        match self {
            Self::Root(fs) => Self::Root(root_fs_mut()),
            Self::Folder(fd) => Self::Folder(Arc::clone(fd)),
        }
    }
}

impl Parent {
    /// Get the name of this parent.
    pub async fn name(&self) -> OsString {
        match self {
            Self::Root(fs) => fs.name.clone(),
            Self::Folder(fd) => {
                let fd = fd.read().await;
                fd.name().clone()
            }
        }
    }

    /// Create a directory in this parent.
    pub async fn mkdir(&mut self, name: OsString) -> Result<Fd> {
        let fd = MemoryFd::Dir(MemoryDir::new_parent(
            name.clone(),
            Some(self.clone()),
        ));
        let dir = Arc::new(RwLock::new(fd));
        self.insert(name, Arc::clone(&dir)).await?;
        Ok(dir)
    }

    /// Remove a child file or directory.
    pub async fn unlink(
        &mut self,
        path: impl AsRef<Path>,
    ) -> Result<Option<Fd>> {
        match self {
            Self::Root(fs) => Ok((*fs).unlink(path)),
            Self::Folder(fd) => {
                let mut fd = fd.write().await;
                match &mut *fd {
                    MemoryFd::Dir(dir) => Ok(dir.unlink(path)),
                    _ => Err(ErrorKind::PermissionDenied.into()),
                }
            }
        }
    }

    /// Insert a child node into this parent.
    ///
    /// If a child already exists with the same name it is replaced.
    pub async fn insert(
        &mut self,
        name: OsString,
        child: Fd,
    ) -> Result<()> {
        match self {
            Self::Root(fs) => Ok((*fs).insert(name, child)),
            Self::Folder(fd) => {
                let mut fd = fd.write().await;
                match &mut *fd {
                    MemoryFd::Dir(dir) => Ok(dir.insert(name, child)),
                    _ => Err(ErrorKind::PermissionDenied.into()),
                }
            }
        }
    }
}

/// Directory file descriptor.
#[derive(Default, Debug)]
pub(super) struct MemoryDir {
    name: OsString,
    parent: Option<Parent>,
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
    pub(super) fn new_parent(name: OsString, parent: Option<Parent>) -> Self {
        Self {
            name,
            parent,
            permissions: Default::default(),
            time: Default::default(),
            files: Default::default(),
        }
    }

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    pub(super) fn new_parent(name: OsString, parent: Option<Parent>) -> Self {
        Self {
            name,
            parent,
            permissions: Default::default(),
            files: Default::default(),
        }
    }

    /// Files in this directory.
    pub fn files(&self) -> &FileSystem {
        &self.files
    }

    /// Remove a child file or directory.
    pub fn unlink(&mut self, path: impl AsRef<Path>) -> Option<Fd> {
        if let Some(name) = path.as_ref().file_name() {
            self.files.remove(name)
        } else {
            None
        }
    }

    /// Determine if this directory is the root of the file system.
    pub fn is_root(&self) -> bool {
        self.parent.is_none()
    }
    
    /// Insert a child node into this directory.
    pub fn insert(&mut self, name: OsString, fd: Fd) {
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

/// File content.
#[derive(Debug)]
pub(super) struct MemoryFile {
    name: OsString,
    parent: Option<Parent>,
    permissions: Permissions,
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    time: FileTime,
    pub(super) contents: FileContent,
}

impl MemoryFile {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    fn new(
        name: OsString,
        parent: Option<Parent>,
        contents: Vec<u8>,
    ) -> Self {
        Self {
            name,
            parent,
            permissions: Default::default(),
            time: Default::default(),
            contents: Arc::new(SyncMutex::new(Cursor::new(contents))),
        }
    }

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    fn new(
        name: OsString,
        parent: Option<Parent>,
        contents: Vec<u8>,
    ) -> Self {
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
#[derive(Debug)]
pub(super) enum MemoryFd {
    /// File variant.
    File(MemoryFile),
    /// Directory variant.
    Dir(MemoryDir),
}

impl MemoryFd {
    pub fn parent(&self) -> Option<&Parent> {
        match self {
            Self::File(fd) => fd.parent.as_ref(),
            Self::Dir(fd) => fd.parent.as_ref(),
        }
    }

    pub fn parent_mut(&mut self) -> Option<&mut Parent> {
        match self {
            Self::File(fd) => fd.parent.as_mut(),
            Self::Dir(fd) => fd.parent.as_mut(),
        }
    }

    pub fn name(&self) -> &OsString {
        match self {
            Self::File(fd) => &fd.name,
            Self::Dir(fd) => &fd.name,
        }
    }

    pub async fn path(&self) -> PathBuf {
        let mut parent = self.parent().cloned();
        let mut components = vec![self.name().clone()];
        while let Some(fd) = parent {
            let name = fd.name().await;
            components.push(name);
            parent = match fd {
                Parent::Root(_) => None,
                Parent::Folder(fd) => {
                    let fd = fd.read().await;
                    fd.parent().cloned()
                }
            };
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

/// Creates a future that will open a file for writing
/// and write the entire contents to it.
pub async fn write(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
) -> Result<()> {
    if let Some(target) = resolve(path.as_ref()).await {
        match target {
            PathTarget::Descriptor(fd) => {
                let mut fd = fd.write().await;
                match &mut *fd {
                    MemoryFd::File(fd) => {
                        let buf = fd.contents();
                        let mut data = buf.lock();
                        *data = Cursor::new(contents.as_ref().to_vec());
                        Ok(())
                    }
                    MemoryFd::Dir(_) => {
                        Err(ErrorKind::PermissionDenied.into())
                    }
                }
            }
            _ => Err(ErrorKind::PermissionDenied.into()),
        }
    } else {
        let has_parent = has_parent(path.as_ref());
        if has_parent {
            if let Some(target) = resolve_parent(path.as_ref()).await {
                match target {
                    PathTarget::Descriptor(fd) => {
                        let is_dir = {
                            let fd = fd.read().await;
                            matches!(&*fd, MemoryFd::Dir(_))
                        };
                        if is_dir {
                            create_file(
                                path,
                                contents.as_ref().to_vec(),
                                false,
                            )
                            .await?;
                            Ok(())
                        } else {
                            Err(ErrorKind::PermissionDenied.into())
                        }
                    }
                    _ => Err(ErrorKind::PermissionDenied.into()),
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
    if let Some(target) = resolve(path.as_ref().to_path_buf()).await {
        match target {
            PathTarget::Descriptor(fd) => {
                let fd = fd.read().await;
                if let MemoryFd::File(fd) = &*fd {
                    let buf = fd.contents();
                    let data = buf.lock();
                    Ok((&*data).clone().into_inner())
                } else {
                    Err(ErrorKind::PermissionDenied.into())
                }
            }
            _ => Err(ErrorKind::PermissionDenied.into()),
        }
    } else {
        Err(ErrorKind::NotFound.into())
    }
}

/// Removes a file from the filesystem.
pub async fn remove_file(path: impl AsRef<Path>) -> Result<()> {
    let _ = FS_LOCK.lock().await;

    let file = ensure_file(path.as_ref()).await?;
    let mut fd = file.write().await;
    if let Some(parent) = fd.parent_mut() {
        parent.unlink(path).await?;
        Ok(())
    } else {
        Err(ErrorKind::PermissionDenied.into())
    }
}

/// Removes an existing, empty directory.
pub async fn remove_dir(path: impl AsRef<Path>) -> Result<()> {
    let _ = FS_LOCK.lock().await;

    let dir = ensure_dir(path.as_ref()).await?;
    let mut fd = dir.write().await;
    match &*fd {
        MemoryFd::Dir(dir) => {
            if dir.files().is_empty() {
                if let Some(parent) = fd.parent_mut() {
                    parent.unlink(path).await?;
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
    let mut fd = dir.write().await;
    if let Some(parent) = fd.parent_mut() {
        parent.unlink(path).await?;
        Ok(())
    } else {
        Err(ErrorKind::PermissionDenied.into())
    }
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

    let file = match file {
        PathTarget::Descriptor(fd) => fd,
        _ => return Err(ErrorKind::PermissionDenied.into()),
    };

    let mut fd = file.write().await;

    let from_name = from.as_ref().file_name().ok_or_else(|| {
        let err: io::Error = ErrorKind::PermissionDenied.into();
        err
    })?;

    let to_name = to.as_ref().file_name().ok_or_else(|| {
        let err: io::Error = ErrorKind::PermissionDenied.into();
        err
    })?;

    let source = {
        let parent = fd.parent_mut().ok_or_else(|| {
            let err: io::Error = ErrorKind::PermissionDenied.into();
            err
        })?;
        parent.unlink(from_name).await?
    };

    if let Some(source) = source {
        if let Some(target) = resolve(to.as_ref()).await {
            match target {
                PathTarget::Descriptor(to_fd) => {
                    let mut to_fd = to_fd.write().await;
                    // Overwrite existing file
                    if matches!(&*to_fd, MemoryFd::File(_)) {
                        if let Some(to_parent_fd) = to_fd.parent_mut() {
                            to_parent_fd
                                .insert(to_name.to_owned(), source)
                                .await?;
                        }
                        Ok(())
                    // Cannot overwrite a directory
                    } else {
                        Err(ErrorKind::PermissionDenied.into())
                    }
                }
                _ => Err(ErrorKind::PermissionDenied.into()),
            }
        } else {
            let has_parent = has_parent(to.as_ref()); 
            if has_parent {
                // To does not exist but it's parent must
                if let Some(target) = resolve_parent(to.as_ref()).await {
                    match target {
                        PathTarget::Descriptor(fd) => {
                            let mut to_parent_write = fd.write().await;
                            match &mut *to_parent_write {
                                MemoryFd::Dir(dir) => {
                                    dir.insert(to_name.to_owned(), source);
                                }
                                _ => unreachable!(),
                            }
                        }
                        PathTarget::Root(dir) => {
                            dir.insert(to_name.to_owned(), source);
                        }
                    }
                    Ok(())
                } else {
                    Err(ErrorKind::NotFound.into())
                }

            // Moving to the root
            } else {
                root_fs_mut().insert(to_name.to_owned(), source);
                Ok(())
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
    if let Some(target) = resolve(path.as_ref().to_path_buf()).await {
        match target {
            PathTarget::Descriptor(fd) => {
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
            }
            PathTarget::Root(_) => {
                unimplemented!("support root fs metadata");
            }
        }
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
    if let Some(target) = resolve(path.as_ref()).await {
        match target {
            PathTarget::Descriptor(fd) => {
                let mut fd = fd.write().await;
                fd.set_permissions(perm);
                Ok(())
            }
            _ => Err(ErrorKind::PermissionDenied.into()),
        }
    } else {
        Err(ErrorKind::NotFound.into())
    }
}

/// Returns Ok(true) if the path points at an existing entity.
pub async fn try_exists(path: impl AsRef<Path>) -> Result<bool> {
    log::info!("try_exists {:#?}", path.as_ref());
    Ok(resolve(path).await.is_some())
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
    if let Some(target) = resolve(path.as_ref()).await {
        match target {
            PathTarget::Descriptor(file) => {
                let mut file_fd = file.write().await;
                if let Some(parent) = file_fd.parent() {
                    match &mut *file_fd {
                        MemoryFd::Dir(_) => {
                            Err(ErrorKind::PermissionDenied.into())
                        }
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
            }
            _ => Err(ErrorKind::PermissionDenied.into()),
        }
    // Try to create in parent
    } else {
        if let Some(target) = resolve_parent(path.as_ref()).await {
            match target {
                PathTarget::Descriptor(fd) => {
                    let mut parent_fd = fd.write().await;
                    match &mut *parent_fd {
                        MemoryFd::Dir(dir) => {
                            let new_file = MemoryFd::File(MemoryFile::new(
                                file_name.to_owned(),
                                Some(Parent::Folder(Arc::clone(&fd))),
                                contents,
                            ));
                            dir.insert(
                                file_name.to_owned(),
                                Arc::new(RwLock::new(new_file)),
                            );
                            Ok(dir.files().get(file_name).map(Arc::clone).unwrap())
                        }
                        MemoryFd::File(_) => {
                            Err(ErrorKind::PermissionDenied.into())
                        }
                    }
                }
                _ => unreachable!(),
            }
        // Create at the root
        } else {
            let dir = root_fs_mut();
            let new_file = MemoryFd::File(MemoryFile::new(
                file_name.to_owned(),
                Some(Parent::Root(root_fs_mut())),
                contents,
            ));
            dir.insert(
                file_name.to_owned(),
                Arc::new(RwLock::new(new_file)),
            );
            Ok(dir.files().get(file_name).map(Arc::clone).unwrap())
        }
    }
}

/// Ensure a path is a file and exists.
async fn ensure_file(path: impl AsRef<Path>) -> Result<Fd> {
    if let Some(target) = resolve(path.as_ref().to_path_buf()).await {
        match target {
            PathTarget::Descriptor(fd) => {
                let is_file = {
                    let fd = fd.read().await;
                    matches!(&*fd, MemoryFd::File(_))
                };
                if is_file {
                    Ok(fd)
                } else {
                    Err(ErrorKind::PermissionDenied.into())
                }
            }
            _ => Err(ErrorKind::PermissionDenied.into()),
        }
    } else {
        Err(ErrorKind::NotFound.into())
    }
}

/// Ensure a path is a directory and exists.
async fn ensure_dir(path: impl AsRef<Path>) -> Result<Fd> {
    if let Some(target) = resolve(path.as_ref().to_path_buf()).await {
        match target {
            PathTarget::Descriptor(fd) => {
                let is_dir = {
                    let fd = fd.read().await;
                    matches!(&*fd, MemoryFd::Dir(_))
                };
                if is_dir {
                    Ok(fd)
                } else {
                    Err(ErrorKind::PermissionDenied.into())
                }
            }
            _ => Err(ErrorKind::PermissionDenied.into()),
        }
    } else {
        Err(ErrorKind::NotFound.into())
    }
}

/// Determine if a path has a parent that is not the root.
pub(super) fn has_parent(path: impl AsRef<Path>) -> bool {
    if let Some(parent) = path.as_ref().parent() {
        !parent.as_os_str().is_empty()
    } else {
        false
    }
}

/// Recursive walk of the tree to find a target path.
#[async_recursion]
async fn walk(
    target: &MemoryDir,
    it: &mut Enumerate<IntoIter<Component>>,
    length: usize,
    parents: &mut Vec<Parent>,
) -> Option<PathTarget> {
    if let Some((index, part)) = it.next() {
        match part {
            Component::RootDir => {
                // Got a root request only
                if length == 1 {
                    return Some(PathTarget::Root(root_fs_mut()));
                }
                parents.push(Parent::Root(root_fs_mut()));
                return walk(root_fs(), it, length, parents).await;
            }
            Component::Normal(name) => {
                if index == length - 1 {
                    return target
                        .files
                        .get(name)
                        .map(|fd| PathTarget::Descriptor(Arc::clone(fd)));
                } else {
                    if let Some(child) = target.find_dir(name).await {
                        parents.push(Parent::Folder(Arc::clone(&child)));
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

/// Resolve relative to a folder.
pub(super) async fn resolve_relative(
    fs: &MemoryDir,
    path: impl AsRef<Path>,
) -> Option<PathTarget> {
    let components: Vec<Component> =
        path.as_ref().components().into_iter().collect();
    let length = components.len();
    let mut it = components.into_iter().enumerate();
    walk(fs, &mut it, length, &mut vec![]).await
}

/// Resolve relative to the root folder.
pub(super) async fn resolve(path: impl AsRef<Path>) -> Option<PathTarget> {
    resolve_relative(root_fs(), path).await
}

/// Try to resolve the parent of a path.
pub(super) async fn resolve_parent(
    path: impl AsRef<Path>,
) -> Option<PathTarget> {
    if let Some(parent) = path.as_ref().parent() {
        resolve(parent).await
    } else {
        None
    }
}
