use sos_backend::Preferences;
use sos_preferences::PreferenceManager;
use std::path::PathBuf;

/// Helper executable used to test concurrent writes
/// to the global preferences file.
#[doc(hidden)]
#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().into_iter().collect::<Vec<_>>();

    // Callers must pass a data directory so that each
    // test is isolated
    let data_dir = args.pop().map(PathBuf::from);

    // Value to write
    let value = args.pop().unwrap();

    let mut preferences = Preferences::new_fs_directory(data_dir)?;
    preferences.load_global_preferences().await?;

    let prefs = preferences.global_preferences();
    let mut prefs = prefs.lock().await;
    prefs
        .insert("concurrent.string".to_owned(), value.into())
        .await?;

    Ok(())
}
