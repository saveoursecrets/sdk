/// Forwards Native Messaging API JSON requests to an
/// in-memory web service.
#[doc(hidden)]
#[tokio::main(flavor = "current_thread")]
pub async fn main() -> anyhow::Result<()> {
    sos_extension_service::run().await
}
