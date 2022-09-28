//! Macro utilities for network connections and providers.

/// Retry a request after renewing a session if an
/// UNAUTHORIZED response is returned,
#[macro_export]
macro_rules! retry {
    ($future:expr, $client:expr) => {{
        let future = $future();
        let maybe_retry = future.await?;

        match maybe_retry {
            MaybeRetry::Retry(status) => {
                if status == StatusCode::UNAUTHORIZED && $client.has_session()
                {
                    tracing::debug!("renew client session");
                    $client.authenticate().await?;
                    let future = $future();
                    let maybe_retry = future.await?;
                    match maybe_retry {
                        MaybeRetry::Retry(status) => {
                            if status == StatusCode::UNAUTHORIZED {
                                return Err(Error::NotAuthorized);
                            } else {
                                return Err(Error::ResponseCode(
                                    status.into(),
                                ));
                            }
                        }
                        MaybeRetry::Complete(status, result) => {
                            (status, result)
                        }
                    }
                } else {
                    return Err(Error::NotAuthorized);
                }
            }
            MaybeRetry::Complete(status, result) => (status, result),
        }
    }};
}

/// Patch remote and detect if local is behind remote.
///
/// When local is behind remote attempt to pull changes from
/// remote and apply the patch if the pull succeeds.
#[macro_export]
macro_rules! patch {
    ($provider:expr, $summary:expr, $events:expr) => {{
        let (wal_file, patch_file) = $provider
            .cache
            .get_mut($summary.id())
            .ok_or(Error::CacheNotAvailable(*$summary.id()))?;

        let result = sync::patch(
            &mut $provider.client,
            $summary,
            wal_file,
            patch_file,
            $events
        ).await;

        match result {
            Ok(_) => return Ok(()),
            Err(e) => match e {

                Error::ConflictBehind { events, local, remote, .. } => {
                    tracing::debug!(
                        local = %local.0,
                        remote = %remote.0,
                        "conflict on patch, attempting sync");

                    // Pull the WAL from the server that we
                    // are behind
                    sync::pull_wal(
                        &mut $provider.client,
                        $summary,
                        wal_file
                    ).await?;

                    tracing::debug!(vault_id = %$summary.id(),
                        "conflict on patch, pulled remote WAL");

                    // Retry sending our local changes to
                    // the remote WAL
                    let status = sync::apply_patch(
                        &mut $provider.client,
                        $summary,
                        wal_file,
                        patch_file,
                        events,
                    )
                    .await?;

                    tracing::debug!(status = %status,
                        "conflict on patch, retry patch status");

                    if status.is_success() {
                        // If the retry was successful then
                        // we should update the in-memory vault
                        // so if reflects the pulled changes
                        // with our patch applied over the top
                        let updated_vault =
                            $provider.reduce_wal($summary)?;

                        if let Some(keeper) = $provider.current_mut() {
                            if keeper.id() == $summary.id() {
                                let existing_vault = keeper.vault_mut();
                                *existing_vault = updated_vault;
                            }
                        }

                        Ok(())
                    } else {
                        Err(Error::ResponseCode(status.into()))
                    }
                }
                _ => return Err(e),
            },
        }
    }}
}
