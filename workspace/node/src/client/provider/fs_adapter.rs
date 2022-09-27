//! Adapter for file system operations that are noop in webassembly.

#[cfg(not(target_arch = "wasm32"))]
pub use fs::*;

#[cfg(not(target_arch = "wasm32"))]
mod fs {
    use crate::client::Result;
    use std::path::Path;

    pub async fn remove_file(path: impl AsRef<Path>) -> Result<()> {
        Ok(tokio::fs::remove_file(path).await?)
    }

    pub async fn rename(
        from: impl AsRef<Path>,
        to: impl AsRef<Path>,
    ) -> Result<()> {
        Ok(tokio::fs::rename(from, to).await?)
    }

    pub async fn write(
        path: impl AsRef<Path>,
        contents: impl AsRef<[u8]>,
    ) -> Result<()> {
        Ok(tokio::fs::write(path, contents).await?)
    }
}

#[cfg(target_arch = "wasm32")]
pub use noop::*;

#[cfg(target_arch = "wasm32")]
mod noop {
    use crate::client::Result;
    use std::path::Path;

    pub async fn remove_file(_path: impl AsRef<Path>) -> Result<()> {
        Ok(())
    }

    /*
    pub async fn rename(
        _from: impl AsRef<Path>,
        _to: impl AsRef<Path>,
    ) -> Result<()> {
        Ok(())
    }

    pub async fn write(
        _path: impl AsRef<Path>,
        _contents: impl AsRef<[u8]>,
    ) -> Result<()> {
        Ok(())
    }
    */
}
