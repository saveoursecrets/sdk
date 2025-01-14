use crate::{
    db::{AccountEntity, ServerEntity},
    Error,
};
use async_sqlite::Client;
use async_trait::async_trait;
use sos_core::{AccountId, Origin, RemoteOrigins};
use std::collections::HashSet;

/// Collection of server origins.
pub struct ServerOrigins<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<Error>
        + Send
        + Sync
        + 'static,
{
    client: Client,
    account_id: AccountId,
    marker: std::marker::PhantomData<E>,
}

impl<E> ServerOrigins<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<Error>
        + Send
        + Sync
        + 'static,
{
    /// Create new server origins.
    pub fn new(client: Client, account_id: AccountId) -> Self {
        Self {
            client,
            account_id,
            marker: std::marker::PhantomData,
        }
    }

    async fn load_origins(&self) -> Result<HashSet<Origin>, E> {
        let account_id = self.account_id.clone();
        let servers = self
            .client
            .conn_and_then(move |conn| {
                let accounts = AccountEntity::new(&conn);
                let account_row = accounts.find_one(&account_id)?;
                let servers = ServerEntity::new(&conn);
                Ok(servers.load_servers(account_row.row_id)?)
            })
            .await?;
        let mut set = HashSet::new();
        for server in servers {
            set.insert(server.try_into()?);
        }
        Ok(set)
    }

    async fn insert_server(
        &mut self,
        origin: Origin,
        remove: Option<&Origin>,
    ) -> Result<(), E> {
        let account_id = self.account_id.clone();
        let remove = remove.cloned();
        self.client
            .conn_mut(move |conn| {
                let tx = conn.transaction()?;
                let accounts = AccountEntity::new(&tx);
                let account_row = accounts.find_one(&account_id)?;
                let servers = ServerEntity::new(&tx);
                if let Some(remove) = remove {
                    let server_row =
                        servers.find_one(account_row.row_id, remove.url())?;
                    servers.delete_server(server_row.row_id)?;
                }

                Ok(servers.insert_server(account_row.row_id, origin)?)
            })
            .await
            .map_err(Error::from)?;
        Ok(())
    }
}

#[async_trait]
impl<E> RemoteOrigins for ServerOrigins<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<Error>
        + Send
        + Sync
        + 'static,
{
    type Error = E;

    async fn load_servers(&self) -> Result<HashSet<Origin>, Self::Error> {
        self.load_origins().await
    }

    async fn add_server(
        &mut self,
        origin: Origin,
    ) -> Result<(), Self::Error> {
        self.insert_server(origin, None).await
    }

    async fn replace_server(
        &mut self,
        old_origin: &Origin,
        new_origin: Origin,
    ) -> Result<(), Self::Error> {
        self.insert_server(new_origin, Some(old_origin)).await
    }

    async fn remove_server(
        &mut self,
        origin: &Origin,
    ) -> Result<(), Self::Error> {
        let account_id = self.account_id.clone();
        let origin = origin.clone();
        self.client
            .conn(move |conn| {
                let accounts = AccountEntity::new(&conn);
                let account_row = accounts.find_one(&account_id)?;
                let servers = ServerEntity::new(&conn);
                let server_row =
                    servers.find_one(account_row.row_id, origin.url())?;
                Ok(servers.delete_server(server_row.row_id)?)
            })
            .await
            .map_err(Error::from)?;

        Ok(())
    }
}
