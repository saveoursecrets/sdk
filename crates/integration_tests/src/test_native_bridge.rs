use sos_ipc::native_bridge::server::{
    NativeBridgeOptions, NativeBridgeServer,
};

/// Executable used to test the native bridge.
#[doc(hidden)]
#[tokio::main]
pub async fn main() {
    let mut args = std::env::args().into_iter().collect::<Vec<_>>();

    let socket_name = args.pop().unwrap_or_else(String::new).to_string();
    let extension_id = args.pop().unwrap_or_else(String::new).to_string();

    let options =
        NativeBridgeOptions::with_socket_name(extension_id, socket_name);
    let server = NativeBridgeServer::new(options);
    server.listen().await
}
