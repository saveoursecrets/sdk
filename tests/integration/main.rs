use anyhow::{Error, Result};
use serial_test::serial;

mod test_utils;

use test_utils::*;

use sos_client::signup;

#[tokio::test]
#[serial]
async fn signup_account() -> Result<()> {
    println!("signup account!!");

    let dir = integration_test_dir();
    let (rx, handle) = spawn()?;
    let _ = rx.await?;

    Ok(())
}

#[tokio::test]
#[serial]
async fn another_test() -> Result<()> {
    println!("another test!!");

    let dir = integration_test_dir();
    let (rx, handle) = spawn()?;
    let _ = rx.await?;

    Ok(())
}
