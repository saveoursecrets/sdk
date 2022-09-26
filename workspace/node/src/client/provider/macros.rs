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
