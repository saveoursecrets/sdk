use crate::{write_exclusive, Error};
use async_fd_lock::LockRead;
use async_trait::async_trait;
use sos_core::{Origin, Paths, RemoteOrigins};
use sos_vfs::{self as vfs, File};
use std::{collections::HashSet, sync::Arc};
use tokio::io::AsyncReadExt;

/// Collection of server origins.
pub struct ServerOrigins<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    paths: Arc<Paths>,
    marker: std::marker::PhantomData<E>,
}

impl<E> ServerOrigins<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    /// Create new server origins.
    pub fn new(paths: Arc<Paths>) -> Self {
        Self {
            paths,
            marker: std::marker::PhantomData,
        }
    }

    async fn list_origins(&self) -> Result<HashSet<Origin>, E> {
        let remotes_file = self.paths.remote_origins();
        if vfs::try_exists(&remotes_file).await? {
            let file = File::open(&remotes_file).await?;
            let mut guard = file.lock_read().await.map_err(|e| e.error)?;
            let mut content = Vec::new();
            guard.read_to_end(&mut content).await?;

            let origins: HashSet<Origin> =
                serde_json::from_slice(&content).map_err(Error::from)?;
            Ok(origins)
        } else {
            Ok(Default::default())
        }
    }

    async fn save_origins(&self, origins: &HashSet<Origin>) -> Result<(), E> {
        let data =
            serde_json::to_vec_pretty(&origins).map_err(Error::from)?;
        let file = self.paths.remote_origins();
        write_exclusive(file, data).await?;
        Ok(())
    }
}

#[async_trait]
impl<E> RemoteOrigins for ServerOrigins<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    type Error = E;

    async fn list_servers(&self) -> Result<HashSet<Origin>, Self::Error> {
        self.list_origins().await
    }

    async fn add_server(
        &mut self,
        origin: Origin,
    ) -> Result<(), Self::Error> {
        let mut origins = self.list_origins().await?;
        origins.insert(origin);
        self.save_origins(&origins).await?;
        Ok(())
    }

    async fn replace_server(
        &mut self,
        old_origin: &Origin,
        new_origin: Origin,
    ) -> Result<(), Self::Error> {
        self.remove_server(old_origin).await?;
        self.add_server(new_origin).await?;
        Ok(())
    }

    async fn remove_server(
        &mut self,
        origin: &Origin,
    ) -> Result<(), Self::Error> {
        let mut origins = self.list_origins().await?;
        origins.remove(origin);
        self.save_origins(&origins).await?;
        Ok(())
    }
}
