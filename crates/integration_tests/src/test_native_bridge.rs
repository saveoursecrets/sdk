use http::StatusCode;
use sos_ipc::{
    local_transport::{HttpMessage, LocalRequest, LocalResponse},
    native_bridge::server::{
        NativeBridgeOptions, NativeBridgeServer, RouteFuture,
    },
};

#[macro_export]
#[allow(missing_fragment_specifier)]
macro_rules! println {
    ($($any:tt)*) => {
        compile_error!("println! macro is forbidden, use eprintln! instead");
    };
}

const MB: usize = 1024 * 1024;

fn large_file(request: LocalRequest) -> RouteFuture {
    Box::pin(async move {
        let message_id = request.request_id();
        let mut res = LocalResponse::with_id(StatusCode::OK, message_id);
        res.body = [255u8; MB].to_vec();
        Ok(res)
    })
}

/// Executable used to test the native bridge.
#[doc(hidden)]
#[tokio::main]
pub async fn main() {
    let mut args = std::env::args().into_iter().collect::<Vec<_>>();

    let socket_name = args.pop().unwrap_or_else(String::new).to_string();
    let extension_id = args.pop().unwrap_or_else(String::new).to_string();

    let options =
        NativeBridgeOptions::with_socket_name(extension_id, socket_name);
    let mut server = NativeBridgeServer::new(options);
    server.add_intercept_route("/large-file".to_string(), large_file as _);
    server.listen().await
}
