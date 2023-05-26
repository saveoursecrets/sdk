//! File system backed by in-memory buffers.

use bitflags::bitflags;
use async_recursion::async_recursion;
use once_cell::sync::Lazy;
use std::{
    collections::BTreeMap,
    io::{self, Error, ErrorKind},
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use tokio::sync::{Mutex, RwLock};

mod file;
mod meta_data;
mod open_options;
pub use file::File;
pub use meta_data::{Metadata, Permissions};
pub use open_options::OpenOptions;

use meta_data::FileTime;

/// Result type for the in-memory file system.
pub type Result<T> = std::result::Result<T, Error>;

bitflags! {
    /// Bit flags a file descriptor.
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
type FileSystem = BTreeMap<PathBuf, Fd>;

// File system contents.
pub(self) static mut FILE_SYSTEM: Lazy<MemoryDir> =
    Lazy::new(|| MemoryDir::new_root());

// Lock for when we need to modify the file system by adding
// or removing paths.
static FS_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

#[async_recursion]
pub(self) async fn find(
    fs: &MemoryDir,
    path: PathBuf,
) -> Option<Arc<RwLock<MemoryFd>>> {
    if fs.root && path.is_relative() {
        return None
    }

    let components: Vec<Component> =
        path.components().into_iter().collect();
    let length = components.len();
    let mut it = components.into_iter();
    for (index, part) in it.clone().enumerate() {
        match part {
            Component::RootDir => continue,
            Component::Normal(name) => {
                let path = PathBuf::from(name);
                if index < length - 1 {
                    if let Some(child) = fs.find_dir(path).await {
                        let fd = child.read().await;
                        if let MemoryFd::Dir(dir) = &*fd {
                            if let Some(next) = it.next() {
                                match next {
                                    Component::Normal(name) => {
                                        let path = PathBuf::from(name);
                                        return find(dir, path).await;
                                    }
                                    _ => todo!(),
                                }
                            } else {
                                return None
                            }
                        }
                    } else {
                        return None
                    }
                } else {
                    //return fs.get(&path).map(Arc::clone);
                    todo!();
                }
            }
            _ => todo!(),
        }
    }
    None
}

/// Directory reference.
#[derive(Default, Debug)]
pub(self) struct MemoryDir {
    root: bool,
    permissions: Permissions,
    time: FileTime,
    files: FileSystem,
}

impl MemoryDir {
    fn new_root() -> Self {
        Self {
            root: true,
            permissions: Default::default(),
            time: Default::default(),
            files: Default::default(),
        }
    }

    /// Determine if the file is empty.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Get the length.
    pub fn len(&self) -> usize {
        self.files.len()
    }
    
    /// Find a child that is a dir.
    async fn find_dir(&self, path: impl AsRef<Path>) -> Option<Fd> {
        if let Some(child) = self.files.get(path.as_ref()) {
            let is_dir = {
                let fd = child.read().await;
                matches!(&*fd, MemoryFd::Dir(_))
            };
            if is_dir { Some(Arc::clone(child)) } else { None }
        } else {
            None
        }
    }
}

/// File content.
#[derive(Default, Debug)]
pub(self) struct MemoryFile {
    permissions: Permissions,
    time: FileTime,
    pub(self) contents: Vec<u8>,
}

impl MemoryFile {
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
pub(self) enum MemoryFd {
    /// File variant.
    File(MemoryFile),
    /// Directory variant.
    Dir(MemoryDir),
}

impl MemoryFd {
    /// Determine if the file is empty.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::File(fd) => fd.is_empty(),
            Self::Dir(fd) => fd.is_empty(),
        }
    }

    /// Get the length.
    pub fn len(&self) -> usize {
        match self {
            Self::File(fd) => fd.len(),
            Self::Dir(fd) => fd.len(),
        }
    }

    pub(crate) fn flags(&self) -> FileFlags {
        match self {
            Self::File(_) => FileFlags::FILE,
            Self::Dir(_) => FileFlags::DIR,
        }
    }

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

    pub(crate) fn metadata(&self) -> Metadata {
        Metadata::new(
            self.permissions().clone(),
            self.time().clone(),
            self.flags(),
            self.len() as u64,
        )
    }
}

/// Ensure a path is a file and exists.
async fn ensure_file(path: impl AsRef<Path>) -> Result<()> {
    unsafe {
        let fs = Lazy::get(&mut FILE_SYSTEM).unwrap();
        let fd = find(&fs, path.as_ref().to_path_buf()).await;
        if let Some(fd) = fd {
            let fd = fd.read().await;
            let is_file = matches!(&*fd, MemoryFd::File(_));
            if !is_file {
                return Err(ErrorKind::PermissionDenied.into());
            }
        } else {
            return Err(ErrorKind::NotFound.into());
        }
    }
    Ok(())
}

/// Ensure a path is a directory and exists.
async fn ensure_dir(path: impl AsRef<Path>) -> Result<()> {
    unsafe {
        let fs = Lazy::get(&mut FILE_SYSTEM).unwrap();
        if let Some(fd) = find(&fs, path.as_ref().to_path_buf()).await {
            let fd = fd.read().await;
            let is_file = matches!(&*fd, MemoryFd::Dir(_));
            if !is_file {
                return Err(ErrorKind::PermissionDenied.into());
            }
        } else {
            return Err(ErrorKind::NotFound.into());
        }
    }
    Ok(())
}

/// Find all the descendants of a path.
async fn find_descendants(
    fs: &FileSystem,
    path: impl AsRef<Path>,
) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for (target, file) in fs.iter() {
        if target.starts_with(path.as_ref()) && target != path.as_ref() {
            paths.push(target.clone());
        }
    }
    paths
}

/// Determine if a path is a file.
async fn is_file(fs: &FileSystem, path: impl AsRef<Path>) -> bool {
    if let Some(fd) = fs.get(path.as_ref()) {
        let fd = fd.read().await;
        matches!(&*fd, MemoryFd::File(_))
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
    let path = path.as_ref().to_path_buf();
    unsafe {
        let fs = Lazy::get_mut(&mut FILE_SYSTEM).unwrap();
        if let Some(parent) = path.parent() {
            if let Some(parent) = fs.files.get(parent) {
                let fd = parent.read().await;
                let is_dir = matches!(&*fd, MemoryFd::Dir(_));
                if !is_dir {
                    return Err(ErrorKind::PermissionDenied.into());
                }
            }
        }
        let fd = fs.files.entry(path).or_insert_with(|| {
            Arc::new(RwLock::new(MemoryFd::File(Default::default())))
        });
        let mut fd = fd.write().await;
        if let MemoryFd::File(fd) = &mut *fd {
            fd.contents = contents.as_ref().to_vec();
        }
    }
    Ok(())
}

/// Reads the entire contents of a file into a bytes vector.
pub async fn read(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    unsafe {
        let fs = Lazy::get(&mut FILE_SYSTEM).unwrap();
        if let Some(fd) = find(&fs, path.as_ref().to_path_buf()).await {
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
}

/// Removes a file from the filesystem.
pub async fn remove_file(path: impl AsRef<Path>) -> Result<()> {
    ensure_file(path.as_ref()).await?;

    let _ = FS_LOCK.lock().await;
    unsafe {
        let fs = Lazy::get_mut(&mut FILE_SYSTEM).unwrap();
        fs.files.remove(path.as_ref());
    }
    Ok(())
}

/// Removes an existing, empty directory.
pub async fn remove_dir(path: impl AsRef<Path>) -> Result<()> {
    ensure_dir(path.as_ref()).await?;

    // FIXME: ensure directory is empty

    let _ = FS_LOCK.lock().await;
    unsafe {
        let fs = Lazy::get_mut(&mut FILE_SYSTEM).unwrap();
        fs.files.remove(path.as_ref());
    }

    Ok(())
}

/// Removes a directory at this path, after removing
/// all its contents. Use carefully!
pub async fn remove_dir_all(path: impl AsRef<Path>) -> Result<()> {
    unsafe {
        let fs = Lazy::get_mut(&mut FILE_SYSTEM).unwrap();
        if let Some(fd) = find(&fs, path.as_ref().to_path_buf()).await {
            let fd = fd.read().await;
            let is_dir = matches!(&*fd, MemoryFd::Dir(_));
            if is_dir {
                /*
                let descendants =
                    find_descendants(&*FILE_SYSTEM, path.as_ref()).await;
                for child in descendants {
                    if is_file(&*FILE_SYSTEM, &child).await {
                        remove_file(&child).await?;
                    } else {
                        remove_dir(&child).await?;
                    }
                }
                */
                Ok(())
            } else {
                Err(ErrorKind::PermissionDenied.into())
            }
        } else {
            Err(ErrorKind::NotFound.into())
        }
    }
}

/// Renames a file or directory to a new name, replacing
/// the original file if to already exists.
pub async fn rename(
    from: impl AsRef<Path>,
    to: impl AsRef<Path>,
) -> Result<()> {
    let _ = FS_LOCK.lock().await;

    unsafe {
        let fs = Lazy::get_mut(&mut FILE_SYSTEM).unwrap();
        if let Some(fd) = fs.files.remove(from.as_ref()) {
            fs.files.insert(to.as_ref().to_path_buf(), fd);
            Ok(())
        } else {
            Err(ErrorKind::NotFound.into())
        }
    }
}

/// Creates a new, empty directory at the provided path.
pub async fn create_dir(path: impl AsRef<Path>) -> Result<()> {
    let _ = FS_LOCK.lock().await;

    let path = path.as_ref().to_path_buf();
    unsafe {
        let fs = Lazy::get_mut(&mut FILE_SYSTEM).unwrap();

        if let Some(parent) = path.parent() {
            if let Some(parent) = find(&fs, parent.to_path_buf()).await {
                let parent = parent.read().await;
                let is_dir = matches!(&*parent, MemoryFd::Dir(_));
                if !is_dir {
                    return Err(ErrorKind::PermissionDenied.into());
                }
            }
        }
        fs.files.entry(path).or_insert_with(|| {
            Arc::new(RwLock::new(MemoryFd::Dir(Default::default())))
        });
    }
    Ok(())
}

/// Recursively creates a directory and all of its parent
/// components if they are missing.
pub async fn create_dir_all(path: impl AsRef<Path>) -> Result<()> {
    let _ = FS_LOCK.lock().await;
    let path = path.as_ref().to_path_buf();

    unsafe {
        let fs = Lazy::get_mut(&mut FILE_SYSTEM).unwrap();
        // FIXME: ensure all parents do not exist
        // FIXME: or that all parents are directories
        fs.files.entry(path).or_insert_with(|| {
            Arc::new(RwLock::new(MemoryFd::Dir(Default::default())))
        });
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
    unsafe {
        let fs = Lazy::get(&mut FILE_SYSTEM).unwrap();
        if let Some(fd) = find(&fs, path.as_ref().to_path_buf()).await {
            let fd = fd.read().await;
            Ok(fd.metadata())
        } else {
            Err(ErrorKind::NotFound.into())
        }
    }
}

/// Changes the permissions found on a file or a directory.
pub async fn set_permissions(
    path: impl AsRef<Path>,
    perm: Permissions,
) -> Result<()> {
    unsafe {
        let fs = Lazy::get_mut(&mut FILE_SYSTEM).unwrap();
        if let Some(fd) = fs.files.get_mut(path.as_ref()) {
            let mut fd = fd.write().await;
            fd.set_permissions(perm);
            Ok(())
        } else {
            Err(ErrorKind::NotFound.into())
        }
    }
}

/*
/// Returns a stream over the entries within a directory.
pub async fn read_dir(path: impl AsRef<Path>) -> Result<ReadDir> {
    todo!();
}
*/
