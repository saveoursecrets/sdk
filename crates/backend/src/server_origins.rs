use crate::Error;
use async_trait::async_trait;
use sos_core::{AccountId, Origin, Paths, RemoteOrigins};
use sos_database::{async_sqlite::Client, ServerOrigins as DbServerOrigins};
use sos_filesystem::ServerOrigins as FsServerOrigins;
use std::{collections::HashSet, sync::Arc};

type BoxedServerOrigins =
    Box<dyn RemoteOrigins<Error = Error> + Send + Sync + 'static>;

/// Collection of server origins.
pub struct ServerOrigins(BoxedServerOrigins);

impl ServerOrigins {
    /// Create file system server origins.
    pub fn new_fs(paths: Arc<Paths>) -> Self {
        Self(Box::new(FsServerOrigins::new(paths)))
    }

    /// Create database server origins.
    pub fn new_db(client: Client, account_id: AccountId) -> Self {
        Self(Box::new(DbServerOrigins::new(client, account_id)))
    }
}

#[async_trait]
impl RemoteOrigins for ServerOrigins {
    type Error = Error;

    async fn load_servers(&self) -> Result<HashSet<Origin>, Self::Error> {
        self.0.load_servers().await
    }

    async fn add_server(
        &mut self,
        origin: Origin,
    ) -> Result<(), Self::Error> {
        self.0.add_server(origin).await
    }

    async fn replace_server(
        &mut self,
        old_origin: &Origin,
        new_origin: Origin,
    ) -> Result<(), Self::Error> {
        self.0.replace_server(old_origin, new_origin).await
    }

    async fn remove_server(
        &mut self,
        origin: &Origin,
    ) -> Result<(), Self::Error> {
        self.0.remove_server(origin).await
    }
}
