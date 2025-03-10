//! Consumer for change notifications on a named pipe.
use crate::Result;
use interprocess::local_socket::{
    tokio::prelude::*, GenericNamespaced, ListenerOptions,
};

/// Consumer socket connection for inter-process communication.
pub struct ChangeConsumer;

impl ChangeConsumer {
    /// Listen on a named pipe.
    pub async fn listen(socket_name: &str) -> Result<()> {
        let name = socket_name.to_ns_name::<GenericNamespaced>()?;
        let opts = ListenerOptions::new().name(name);
        let listener = match opts.create_tokio() {
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                tracing::error!(
                    "Error: could not start server because the socket file is occupied. Please check if {socket_name} is in use by another process and try again."
                );
                return Err(e.into());
            }
            x => x?,
        };

        todo!();

        /*
        let service = LocalWebService::new(app_info, accounts);
        let svc = Arc::new(service);

        loop {
            let socket = listener.accept().await?;
            let svc = svc.clone();
            tokio::task::spawn(async move {
                let socket = TokioIo::new(socket);
                let http = Builder::new();

                tracing::debug!("local_socket_server::new_connection");
                let conn = http.serve_connection(socket, svc);
                if let Err(err) = conn.await {
                    tracing::error!(
                      error = %err,
                      "local_socket_server::connection_error");
                }
                tracing::debug!("local_socket_server::connection_close");
            });
        }
        */
    }
}
