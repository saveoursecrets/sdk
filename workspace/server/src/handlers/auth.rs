use axum::{
    extract::{Extension, Path, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::StatusCode,
    Json,
};

//use axum_macros::debug_handler;

use sos_core::{
    events::{AuditEvent, AuditProvider, EventKind},
    vault::Summary,
};

use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    authenticate::{self},
    headers::SignedMessage,
    State,
};

// Handlers for authentication.
pub(crate) struct AuthHandler;
impl AuthHandler {
    /// Issue an authentication challenge.
    ///
    /// The request must be signed in a Authorization header but
    /// the message is chosen by the client. It is recommended the
    /// client choose a 32 byte random payload.
    ///
    /// The signature allows us to determine if an account exists
    /// before creating a challenge.
    ///
    /// The response is a JSON array tuple containing the challenge
    /// identifier as the first element and the 32 byte message to
    /// be signed as the second element.
    pub(crate) async fn challenge(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(message): TypedHeader<SignedMessage>,
    ) -> Result<Json<(Uuid, [u8; 32])>, StatusCode> {
        if let Ok((status_code, token)) =
            authenticate::bearer(authorization, &message)
        {
            if let (StatusCode::OK, Some(token)) = (status_code, token) {
                let mut writer = state.write().await;
                if writer.backend.account_exists(&token.address).await {
                    let log = AuditEvent::new(
                        EventKind::LoginChallenge,
                        token.address,
                        None,
                    );
                    writer
                        .audit_log
                        .append_audit_event(log)
                        .await
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                    let challenge = writer.authentication.new_challenge();
                    Ok(Json(challenge))
                } else {
                    Err(StatusCode::NOT_FOUND)
                }
            } else {
                Err(status_code)
            }
        } else {
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }

    /// Handle the response to a challenge.
    pub(crate) async fn response(
        Extension(state): Extension<Arc<RwLock<State>>>,
        TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
        TypedHeader(message): TypedHeader<SignedMessage>,
        Path(challenge_id): Path<Uuid>,
    ) -> Result<Json<Vec<Summary>>, StatusCode> {
        let mut writer = state.write().await;

        // Immediately remove the identified challenge so we clean
        // up the server state as early as possible. There is a possible
        // DoS here if an intermediary MiTM detected the challenge identifier
        // and submits it before the real client can authenticate then
        // they can be denied access to the vault list.
        if let Some((challenge, _)) =
            writer.authentication.remove(&challenge_id)
        {
            // Body payload must match the challenge corresponding
            // to it's identifier
            if challenge == message.as_ref() {
                // Now check the bearer signature against the body payload
                if let Ok((status_code, token)) =
                    authenticate::bearer(authorization, &message)
                {
                    if let (StatusCode::OK, Some(token)) =
                        (status_code, token)
                    {
                        if !writer
                            .backend
                            .account_exists(&token.address)
                            .await
                        {
                            return Err(StatusCode::NOT_FOUND);
                        }

                        if let Ok(summaries) =
                            writer.backend.list(&token.address).await
                        {
                            let log = AuditEvent::new(
                                EventKind::LoginResponse,
                                token.address,
                                None,
                            );
                            writer
                                .audit_log
                                .append_audit_event(log)
                                .await
                                .map_err(|_| {
                                    StatusCode::INTERNAL_SERVER_ERROR
                                })?;

                            Ok(Json(summaries))
                        } else {
                            Err(StatusCode::INTERNAL_SERVER_ERROR)
                        }
                    } else {
                        Err(status_code)
                    }
                } else {
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            } else {
                Err(StatusCode::BAD_REQUEST)
            }
        } else {
            Err(StatusCode::NOT_FOUND)
        }
    }
}
