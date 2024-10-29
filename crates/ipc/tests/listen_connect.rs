use sos_ipc::{Error, IpcClient, IpcRequest, IpcServer, IpcService, Result};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;

#[tokio::test]
async fn listen_connect() -> Result<()> {
    let service = Arc::new(Mutex::new(IpcService::new()));

    tokio::task::spawn(async move {
        IpcServer::listen("127.0.0.1:5353", service).await?;
        Ok::<(), Error>(())
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut client = IpcClient::connect("127.0.0.1:5353").await?;

    let request = IpcRequest { message_id: 5000 };

    println!("{:#?}", request);

    let response = client.send(request).await?;
    println!("response: {:#?}", response);
    tokio::time::sleep(Duration::from_millis(500)).await;

    Ok(())
}
