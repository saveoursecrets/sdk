//! File system backed by in-memory buffers.

use async_recursion::async_recursion;
use bitflags::bitflags;
use once_cell::sync::Lazy;
use parking_lot::Mutex as SyncMutex;
use std::path::MAIN_SEPARATOR;
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fmt,
    io::{self, Cursor, Error, ErrorKind, Result},
    iter::Enumerate,
    path::{Component, Path, PathBuf},
    sync::Arc,
    vec::IntoIter,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, RwLock},
};

use super::{File, Metadata, Permissions};

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

type FileSystem = BTreeMap<OsString, Fd>;
pub(super) type Fd = Arc<RwLock<MemoryFd>>;
pub(super) type FileContent = Arc<SyncMutex<Cursor<Vec<u8>>>>;

// File system contents.
static mut ROOT_DIR: Lazy<MemoryDir> = Lazy::new(|| MemoryDir::new_root());

// Lock for when we need to modify the file system by adding
// or removing paths.
static FS_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

/*
#[cfg(debug_assertions)]
/// Debug the root of the file system.
pub(super) fn debug_root() {
    println!("{:#?}", root_fs());
}
*/

pub(super) fn root_fs_mut() -> &'static mut MemoryDir {
    unsafe { &mut ROOT_DIR }
}

/// Result of a path lookup.
pub(super) enum PathTarget {
    Root(&'static mut MemoryDir),
    Descriptor(Fd),
}

impl From<Parent> for PathTarget {
    fn from(value: Parent) -> Self {
        match value {
            Parent::Root(fs) => PathTarget::Root(fs),
            Parent::Folder(fd) => PathTarget::Descriptor(fd),
        }
    }
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
            Self::Root(_) => Self::Root(root_fs_mut()),
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
            Self::Root(fs) => Ok((*fs).remove(path).await),
            Self::Folder(fd) => {
                let mut fd = fd.write().await;
                match &mut *fd {
                    MemoryFd::Dir(dir) => Ok(dir.remove(path).await),
                    _ => Err(ErrorKind::PermissionDenied.into()),
                }
            }
        }
    }

    /// Insert a child node into this parent.
    ///
    /// If a child already exists with the same name it is replaced.
    pub async fn insert(&mut self, name: OsString, child: Fd) -> Result<()> {
        match self {
            Self::Root(fs) => Ok((*fs).insert(name, child).await),
            Self::Folder(fd) => {
                let mut fd = fd.write().await;
                match &mut *fd {
                    MemoryFd::Dir(dir) => Ok(dir.insert(name, child).await),
                    _ => Err(ErrorKind::PermissionDenied.into()),
                }
            }
        }
    }

    /// Find a child that is a directory.
    async fn find_dir(&self, name: &OsStr) -> Option<Fd> {
        match self {
            Self::Root(fs) => fs.find_dir(name).await,
            Self::Folder(fd) => {
                let mut fd = fd.write().await;
                match &mut *fd {
                    MemoryFd::Dir(dir) => dir.find_dir(name).await,
                    _ => None,
                }
            }
        }
    }
}

/// Directory file descriptor.
#[derive(Default)]
pub(super) struct MemoryDir {
    name: OsString,
    parent: Option<Parent>,
    permissions: Permissions,
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    time: FileTime,
    files: FileSystem,
}

impl fmt::Debug for MemoryDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryDir")
            .field("name", &self.name)
            .field("permissions", &self.permissions)
            .field("files", &self.files)
            .finish()
    }
}

impl MemoryDir {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    fn new_root() -> Self {
        Self {
            name: OsString::from(MAIN_SEPARATOR.to_string()),
            parent: None,
            permissions: Default::default(),
            time: Default::default(),
            files: Default::default(),
        }
    }

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    fn new_root() -> Self {
        Self {
            name: OsString::from(MAIN_SEPARATOR.to_string()),
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
    pub async fn remove(&mut self, path: impl AsRef<Path>) -> Option<Fd> {
        let _ = FS_LOCK.lock().await;
        if let Some(name) = path.as_ref().file_name() {
            self.files.remove(name)
        } else {
            None
        }
    }

    /// Insert a child node into this directory.
    pub async fn insert(&mut self, name: OsString, fd: Fd) {
        let _ = FS_LOCK.lock().await;
        self.files.insert(name, fd);
    }

    /// Find a child that is a dir.
    pub async fn find_dir(&self, name: &OsStr) -> Option<Fd> {
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
pub(super) struct MemoryFile {
    name: OsString,
    parent: Option<Parent>,
    permissions: Permissions,
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    time: FileTime,
    pub(super) contents: FileContent,
}

impl fmt::Debug for MemoryFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryFile")
            .field("name", &self.name)
            .field("permissions", &self.permissions)
            .field("contents", &self.contents)
            .finish()
    }
}

impl MemoryFile {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    fn new(name: OsString, parent: Option<Parent>) -> Self {
        Self {
            name,
            parent,
            permissions: Default::default(),
            time: Default::default(),
            contents: Arc::new(SyncMutex::new(Cursor::new(Vec::new()))),
        }
    }

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    fn new(name: OsString, parent: Option<Parent>) -> Self {
        Self {
            name,
            parent,
            permissions: Default::default(),
            contents: Arc::new(SyncMutex::new(Cursor::new(Vec::new()))),
        }
    }

    pub fn truncate(&self) {
        let mut lock = self.contents.lock();
        *lock = Cursor::new(Vec::new());
    }

    pub fn contents(&self) -> FileContent {
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

/// Copies the contents of one file to another.
pub async fn copy(
    from: impl AsRef<Path>,
    to: impl AsRef<Path>,
) -> Result<()> {
    // Copy the buffer and permissions to file descriptor.
    async fn copy_fd(
        fd: Fd,
        buffer: Vec<u8>,
        permissions: Permissions,
    ) -> Result<()> {
        let mut fd = fd.write().await;
        match &mut *fd {
            MemoryFd::File(file) => {
                let mut contents = file.contents.lock();
                let buf = contents.get_mut();
                *buf = buffer;
                file.permissions = permissions;
                Ok(())
            }
            _ => Err(ErrorKind::PermissionDenied.into()),
        }
    }

    // From file must exist.
    if let Some(target) = resolve(from.as_ref()).await {
        match target {
            PathTarget::Descriptor(fd) => {
                if from.as_ref() == to.as_ref() {
                    return Ok(());
                }

                let result: Option<(Vec<u8>, Permissions)> = {
                    let fd = fd.read().await;
                    match &*fd {
                        MemoryFd::File(file) => {
                            let permissions = file.permissions.clone();
                            let contents = file.contents.lock();
                            let buffer = contents.get_ref().clone();
                            Some((buffer, permissions))
                        }
                        _ => None,
                    }
                };

                if let Some((buffer, permissions)) = result {
                    // File exists so overwrite it
                    if let Some(target) = resolve(to.as_ref()).await {
                        match target {
                            PathTarget::Descriptor(fd) => {
                                copy_fd(fd, buffer, permissions).await
                            }
                            PathTarget::Root(_) => {
                                Err(ErrorKind::PermissionDenied.into())
                            }
                        }
                    // Try to create in the parent
                    } else {
                        let fd = create_file(to, false).await?;
                        copy_fd(fd, buffer, permissions).await
                    }
                } else {
                    Err(ErrorKind::PermissionDenied.into())
                }
            }
            PathTarget::Root(_) => Err(ErrorKind::PermissionDenied.into()),
        }
    } else {
        Err(ErrorKind::NotFound.into())
    }
}

/// Creates a future that will open a file for writing
/// and write the entire contents to it.
pub async fn write(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
) -> Result<()> {
    let mut fd = File::create(&path).await?;
    fd.write_all(contents.as_ref()).await?;
    fd.flush().await?;
    Ok(())
}

/// Reads the entire contents of a file into a bytes vector.
pub async fn read(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut fd = File::open(path.as_ref()).await?;
    fd.read_to_end(&mut buffer).await?;
    Ok(buffer)
}

/// Removes a file from the filesystem.
pub async fn remove_file(path: impl AsRef<Path>) -> Result<()> {
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
                                    dir.insert(to_name.to_owned(), source)
                                        .await;
                                }
                                _ => unreachable!(),
                            }
                        }
                        PathTarget::Root(dir) => {
                            dir.insert(to_name.to_owned(), source).await;
                        }
                    }
                    Ok(())
                } else {
                    Err(ErrorKind::NotFound.into())
                }

            // Moving to the root
            } else {
                root_fs_mut().insert(to_name.to_owned(), source).await;
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
    Ok(resolve(path).await.is_some())
}

/// Returns the canonical, absolute form of a path with
/// all intermediate components normalized and symbolic links resolved.
pub async fn canonicalize(path: impl AsRef<Path>) -> Result<PathBuf> {
    if let Some(target) = resolve(path.as_ref()).await {
        match target {
            PathTarget::Root(_) => {
                Ok(PathBuf::from(MAIN_SEPARATOR.to_string()))
            }
            PathTarget::Descriptor(fd) => {
                let fd = fd.read().await;
                Ok(fd.path().await)
            }
        }
    } else {
        Err(ErrorKind::NotFound.into())
    }
}

/// Create a new file.
///
/// The parent directory must exist.
pub(super) async fn create_file(
    path: impl AsRef<Path>,
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
                if let Some(_) = file_fd.parent() {
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
                            ));
                            dir.insert(
                                file_name.to_owned(),
                                Arc::new(RwLock::new(new_file)),
                            )
                            .await;

                            Ok(dir
                                .files()
                                .get(file_name)
                                .map(Arc::clone)
                                .unwrap())
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
            ));
            dir.insert(file_name.to_owned(), Arc::new(RwLock::new(new_file)))
                .await;
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
    target: Parent,
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
                return walk(
                    Parent::Root(root_fs_mut()),
                    it,
                    length,
                    parents,
                )
                .await;
            }
            Component::CurDir | Component::Prefix(_) => {
                return walk(target, it, length, parents).await;
            }
            Component::ParentDir => {
                if let Some(_) = parents.pop() {
                    if index == length - 1 {
                        if let Some(target) = parents.pop() {
                            return Some(target.into());
                        } else {
                            return None;
                        }
                    } else {
                        if let Some(last) = parents.last() {
                            return walk(last.clone(), it, length, parents)
                                .await;
                        }
                    }
                } else {
                    return None;
                }
            }
            Component::Normal(name) => {
                if index == length - 1 {
                    return match target {
                        Parent::Root(fs) => fs
                            .files()
                            .get(name)
                            .map(|fd| PathTarget::Descriptor(Arc::clone(fd))),
                        Parent::Folder(fd) => {
                            let fd = fd.read().await;
                            match &*fd {
                                MemoryFd::Dir(dir) => {
                                    dir.files().get(name).map(|fd| {
                                        PathTarget::Descriptor(Arc::clone(fd))
                                    })
                                }
                                _ => None,
                            }
                        }
                    };
                } else {
                    if let Some(child) = target.find_dir(name).await {
                        parents.push(Parent::Folder(Arc::clone(&child)));
                        return walk(
                            Parent::Folder(Arc::clone(&child)),
                            it,
                            length,
                            parents,
                        )
                        .await;
                    } else {
                        return None;
                    }
                }
            }
        }
    }
    None
}

/// Resolve relative to a parent.
async fn resolve_relative(
    parent: Parent,
    path: impl AsRef<Path>,
) -> Option<PathTarget> {
    let components: Vec<Component> =
        path.as_ref().components().into_iter().collect();
    let length = components.len();
    let mut it = components.into_iter().enumerate();
    walk(parent.clone(), &mut it, length, &mut vec![parent]).await
}

/// Resolve relative to the root folder.
pub(super) async fn resolve(path: impl AsRef<Path>) -> Option<PathTarget> {
    resolve_relative(Parent::Root(root_fs_mut()), path).await
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
