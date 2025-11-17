#![allow(clippy::result_large_err)]

#[tokio::main]
async fn main() -> sos::Result<()> {
    sos::run().await
}
