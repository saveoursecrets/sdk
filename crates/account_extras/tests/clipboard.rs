use anyhow::Result;

#[cfg(feature = "clipboard")]
#[tokio::test]
async fn clipboard() -> Result<()> {
    // NOTE: we must run these tests in serial
    // NOTE: as the underlying Clipboard cannot
    // NOTE: be concurrently created on MacOS
    // NOTE: (and possibly other platforms)
    clipboard_timeout().await?;
    clipboard_timeout_preserve().await?;
    Ok(())
}

#[cfg(feature = "clipboard")]
async fn clipboard_timeout() -> Result<()> {
    use sos_account_extras::clipboard::NativeClipboard;
    use std::time::Duration;

    let mut clipboard = NativeClipboard::new_timeout(1)?;
    let text = "mock-secret";

    clipboard.set_text_timeout(text).await?;

    let value = clipboard.get_text()?;
    assert_eq!(text, value);

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Should error when the clipboard is empty
    assert!(clipboard.get_text().is_err());

    Ok(())
}

#[cfg(feature = "clipboard")]
async fn clipboard_timeout_preserve() -> Result<()> {
    use sos_account_extras::clipboard::NativeClipboard;
    use std::time::Duration;

    let mut clipboard = NativeClipboard::new_timeout(1)?;
    let text = "mock-secret";
    let other_value = "mock-value";

    clipboard.set_text_timeout(text).await?;

    let value = clipboard.get_text()?;
    assert_eq!(text, value);

    // Set to another value so the clipboard will not
    // be cleared on timeout
    clipboard.set_text(other_value)?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Verify the clipboard was not cleared on timeout
    let value = clipboard.get_text()?;
    assert_eq!(other_value, value);

    Ok(())
}
