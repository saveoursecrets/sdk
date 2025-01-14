use crate::Error;
use async_trait::async_trait;
use sos_core::{Origin, Paths, RemoteOrigins};
use sos_vfs as vfs;
use std::{collections::HashSet, sync::Arc};

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

    async fn load_origins(&self) -> Result<HashSet<Origin>, E> {
        let remotes_file = self.paths.remote_origins();
        if vfs::try_exists(&remotes_file).await? {
            let contents = vfs::read_exclusive(&remotes_file).await?;
            let origins: HashSet<Origin> =
                serde_json::from_slice(&contents).map_err(Error::from)?;
            Ok(origins)
        } else {
            Ok(Default::default())
        }
    }

    async fn save_origins(&self, origins: &HashSet<Origin>) -> Result<(), E> {
        let data =
            serde_json::to_vec_pretty(&origins).map_err(Error::from)?;
        let file = self.paths.remote_origins();
        vfs::write_exclusive(file, data).await?;
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

    async fn load_servers(&self) -> Result<HashSet<Origin>, Self::Error> {
        self.load_origins().await
    }

    async fn add_server(&self, origin: Origin) -> Result<(), Self::Error> {
        let mut origins = self.load_origins().await?;
        origins.insert(origin);
        self.save_origins(&origins).await?;
        Ok(())
    }

    async fn remove_server(
        &self,
        origin: &Origin,
    ) -> Result<(), Self::Error> {
        let mut origins = self.load_origins().await?;
        origins.remove(origin);
        self.save_origins(&origins).await?;
        Ok(())
    }
}
