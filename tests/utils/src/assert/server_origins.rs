use anyhow::Result;
use sos_backend::ServerOrigins;
use sos_core::{Origin, RemoteOrigins};

/// Assert on server origins.
pub async fn assert_server_origins(
    servers: &mut ServerOrigins,
) -> Result<()> {
    let first_origin =
        Origin::new("first".to_owned(), "https://first.example.com".parse()?);

    let second_origin = Origin::new(
        "second".to_owned(),
        "https://second.example.com".parse()?,
    );

    servers.add_server(first_origin.clone()).await?;
    servers.add_server(second_origin.clone()).await?;

    let origins = servers.load_servers().await?;
    assert_eq!(2, origins.len());

    // Adding with the same URL should not create multiple
    // entries but behave like a set
    servers.add_server(second_origin.clone()).await?;
    let origins = servers.load_servers().await?;
    assert_eq!(2, origins.len());

    servers.remove_server(&second_origin).await?;
    let origins = servers.load_servers().await?;
    assert_eq!(1, origins.len());

    servers.replace_server(&first_origin, second_origin).await?;
    let origins = servers.load_servers().await?;
    assert_eq!(1, origins.len());
    assert_eq!("second", origins.iter().next().unwrap().name());

    Ok(())
}
