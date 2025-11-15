use sos_backend::{BackendTarget, Preferences};
use sos_core::Paths;
use sos_preferences::PreferenceManager;
use std::path::PathBuf;

/// Helper executable used to test concurrent writes
/// to the global preferences file.
#[doc(hidden)]
#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().collect::<Vec<_>>();

    // Callers must pass a data directory so that each
    // test is isolated
    let data_dir = args.pop().map(PathBuf::from).unwrap();
    let paths = Paths::new_client(&data_dir);
    let target = BackendTarget::from_paths(&paths).await?;

    // Value to write
    let value = args.pop().unwrap();

    let mut preferences = Preferences::new(target);
    preferences.load_global_preferences().await?;

    let prefs = preferences.global_preferences();
    let mut prefs = prefs.lock().await;
    prefs
        .insert("concurrent.string".to_owned(), value.into())
        .await?;

    Ok(())
}
