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
    pub fn new(account_id: AccountId, client: Client) -> Self {
        Self {
            client,
            account_id,
            marker: std::marker::PhantomData,
        }
    }

    async fn list_origins(&self) -> Result<HashSet<Origin>, E> {
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

                servers.insert_server(account_row.row_id, origin)?;

                tx.commit()?;
                Ok(())
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

    async fn list_servers(&self) -> Result<HashSet<Origin>, Self::Error> {
        self.list_origins().await
    }

    async fn add_server(
        &mut self,
        origin: Origin,
    ) -> Result<(), Self::Error> {
        let account_id = self.account_id.clone();
        let url = origin.url().clone();
        let server_row = self
            .client
            .conn(move |conn| {
                let accounts = AccountEntity::new(&conn);
                let account_row = accounts.find_one(&account_id)?;
                let servers = ServerEntity::new(&conn);
                Ok(servers.find_optional(account_row.row_id, &url)?)
            })
            .await
            .map_err(Error::from)?;

        match server_row {
            Some(row) => {
                let old_origin: Origin = row.try_into()?;
                self.insert_server(origin, Some(&old_origin)).await
            }
            None => self.insert_server(origin, None).await,
        }
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
            .conn_mut(move |conn| {
                let tx = conn.transaction()?;
                let accounts = AccountEntity::new(&tx);
                let account_row = accounts.find_one(&account_id)?;
                let servers = ServerEntity::new(&tx);
                let server_row =
                    servers.find_one(account_row.row_id, origin.url())?;
                servers.delete_server(server_row.row_id)?;
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(Error::from)?;

        Ok(())
    }
}
