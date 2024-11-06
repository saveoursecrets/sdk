use sos_ipc::native_bridge::{run, NativeBridgeOptions};
use std::process::exit;

/// Executable used to bridge JSON requests from browser extensions
/// using the native messaging API to the IPC channel.
#[doc(hidden)]
#[tokio::main]
pub async fn main() {
    let mut args = std::env::args().into_iter().collect::<Vec<_>>();

    // Firefox passes two arguments, the last is the
    // extension id (from Firefox 55) and Chrome passes
    // a single argument on Mac and Linux. But on windows
    // Chrome also passes a native window handle so we
    // pop that first.
    if cfg!(target_os = "windows") {
        args.pop();
    }
    let extension_id = args.pop().unwrap_or_else(String::new).to_string();

    let options = NativeBridgeOptions::new(extension_id);
    match run(options).await {
        Ok(_) => exit(0),
        Err(e) => {
            eprintln!("{:#?}", e);
            exit(1);
        }
    }
}
