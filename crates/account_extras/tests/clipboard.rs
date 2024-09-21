use anyhow::Result;

#[cfg(feature = "clipboard")]
#[tokio::test]
async fn clipboard_timeout() -> Result<()> {
    use sos_account_extras::clipboard::NativeClipboard;
    use std::time::Duration;

    let mut clipboard = NativeClipboard::new_timeout(2)?;
    let text = "mock-secret";

    clipboard.set_text_timeout(text).await?;

    let value = clipboard.get_text()?;
    assert_eq!(text, value);

    tokio::time::sleep(Duration::from_secs(4)).await;

    // Should error when the clipboard is empty
    assert!(clipboard.get_text().is_err());

    Ok(())
}
