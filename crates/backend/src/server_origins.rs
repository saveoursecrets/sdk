use crate::{BackendTarget, Error};
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
    /// Create new server origins.
    pub fn new(target: BackendTarget, account_id: &AccountId) -> Self {
        match target {
            BackendTarget::FileSystem(paths) => {
                Self(Box::new(FsServerOrigins::new(Arc::new(paths))))
            }
            BackendTarget::Database(_, client) => {
                Self(Box::new(DbServerOrigins::new(*account_id, client)))
            }
        }
    }

    /// Create file system server origins.
    #[deprecated]
    pub fn new_fs(paths: Arc<Paths>) -> Self {
        Self(Box::new(FsServerOrigins::new(paths)))
    }

    /// Create database server origins.
    #[deprecated]
    pub fn new_db(account_id: AccountId, client: Client) -> Self {
        Self(Box::new(DbServerOrigins::new(account_id, client)))
    }
}

#[async_trait]
impl RemoteOrigins for ServerOrigins {
    type Error = Error;

    async fn list_servers(&self) -> Result<HashSet<Origin>, Self::Error> {
        self.0.list_servers().await
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
