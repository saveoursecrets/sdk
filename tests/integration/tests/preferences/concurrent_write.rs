use super::{
    test_preferences_concurrency,
};
use sos_test_utils::{setup, teardown};
use anyhow::Result;
use sos_backend::Preferences;
use sos_preferences::*;
use sos_sdk::prelude::Paths;
use sos_test_utils::make_client_backend;
use tokio::process::Command;

/// Tests concurrent writes to the global preferences.
#[tokio::test]
#[ignore]
async fn preferences_concurrent_write() -> Result<()> {
    const TEST_ID: &str = "preferences_concurrent_write";
    //sos_test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    Paths::scaffold(&data_dir).await?;
    let paths = Paths::new_client(&data_dir);
    let target = make_client_backend(&paths).await?;

    // Spawn processes to modify the global preferences
    let mut futures = Vec::new();
    for i in 0..5 {
        let cmd_dir = data_dir.clone();
        futures.push(async move {
            let dir = cmd_dir.display().to_string();
            let value = i.to_string();
            let (command, arguments) =
                test_preferences_concurrency(&dir, &value);
            let mut child = Command::new(command)
                .args(arguments)
                .spawn()
                .expect("failed to spawn");
            let status = child.wait().await?;
            Ok::<_, anyhow::Error>(status)
        });
    }
    futures::future::try_join_all(futures).await?;

    let mut preferences = Preferences::new(target);
    preferences.load_global_preferences().await?;
    let prefs = preferences.global_preferences();
    let prefs = prefs.lock().await;
    let value = prefs.get_string("concurrent.string")?;
    assert!(matches!(value, Some(Preference::String(_))));

    teardown(TEST_ID).await;

    Ok(())
}
