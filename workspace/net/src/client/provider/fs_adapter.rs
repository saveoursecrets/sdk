//! Adapter for file system operations that are noop in webassembly.

#[cfg(not(target_arch = "wasm32"))]
pub use fs::*;

#[cfg(not(target_arch = "wasm32"))]
mod fs {
    use crate::client::Result;
    use std::path::Path;

    pub fn remove_file(path: impl AsRef<Path>) -> Result<()> {
        Ok(std::fs::remove_file(path)?)
    }

    pub fn rename(
        from: impl AsRef<Path>,
        to: impl AsRef<Path>,
    ) -> Result<()> {
        Ok(std::fs::rename(from, to)?)
    }

    pub fn write(
        path: impl AsRef<Path>,
        contents: impl AsRef<[u8]>,
    ) -> Result<()> {
        Ok(std::fs::write(path, contents)?)
    }
}

#[cfg(target_arch = "wasm32")]
pub use noop::*;

#[cfg(target_arch = "wasm32")]
mod noop {
    use crate::client::Result;
    use std::path::Path;

    pub fn remove_file(_path: impl AsRef<Path>) -> Result<()> {
        Ok(())
    }
}
