use std::time::Duration;

use sos_ipc::{Error, IpcClient, IpcRequest, IpcServer, Result};

#[tokio::test]
async fn listen_connect() -> Result<()> {
    tokio::task::spawn(async move {
        IpcServer::listen("127.0.0.1:5353").await?;
        Ok::<(), Error>(())
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut client = IpcClient::connect("127.0.0.1:5353").await?;

    let request = IpcRequest { message_id: 5000 };

    println!("{:#?}", request);

    client.send(request).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    Ok(())
}
