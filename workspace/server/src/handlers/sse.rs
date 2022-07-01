use axum::{
    extract::{Extension, Query},
    http::StatusCode,
    response::sse::{Event, Sse},
};

use futures::stream::Stream;

//use axum_macros::debug_handler;

use sos_core::{address::AddressStr, events::ChangeEvent};

use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::sync::{
    broadcast::{self, Sender},
    RwLock,
};

use crate::{authenticate::SignedQuery, State};

const MAX_SSE_CONNECTIONS_PER_CLIENT: u8 = 6;

/// State for the server sent events connection for a single
/// authenticated client.
pub struct SseConnection {
    /// Broadcast sender for server sent events.
    ///
    /// Handlers can send messages via this sender to broadcast
    /// to all the connected server sent events for the client.
    pub(crate) tx: Sender<ChangeEvent>,

    /// Number of connected clients, used to know when
    /// the connection state can be disposed of.
    ///
    /// Browsers limit SSE connections per origin to six
    /// so this should be more than enough.
    pub(crate) clients: u8,
}

pub(crate) async fn sse_handler(
    Extension(state): Extension<Arc<RwLock<State>>>,
    Query(params): Query<SignedQuery>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    if let Ok((status_code, token)) = params.bearer() {
        if let (StatusCode::OK, Some(token)) = (status_code, token) {
            let address = token.address;
            let stream_state = Arc::clone(&state);
            // Save the sender side of the channel so other handlers
            // can publish to the server sent events stream
            let mut writer = state.write().await;

            let conn = if let Some(conn) = writer.sse.get_mut(&token.address)
            {
                conn
            } else {
                let (tx, _) = broadcast::channel::<ChangeEvent>(256);
                writer
                    .sse
                    .entry(token.address)
                    .or_insert(SseConnection { tx, clients: 0 })
            };

            if let Some(result) = conn.clients.checked_add(1) {
                if result > MAX_SSE_CONNECTIONS_PER_CLIENT {
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
                conn.clients = result;
            } else {
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }

            let mut rx = conn.tx.subscribe();

            struct Guard {
                state: Arc<RwLock<State>>,
                address: AddressStr,
            }

            impl Drop for Guard {
                fn drop(&mut self) {
                    let state = Arc::clone(&self.state);
                    let address = self.address;

                    tokio::spawn(
                        // Clean up the state removing the channel for the
                        // client when the socket is closed.
                        async move {
                            let mut writer = state.write().await;
                            let clients = if let Some(conn) =
                                writer.sse.get_mut(&address)
                            {
                                conn.clients -= 1;
                                Some(conn.clients)
                            } else {
                                None
                            };

                            if let Some(clients) = clients {
                                if clients == 0 {
                                    writer.sse.remove(&address);
                                }
                            }
                        },
                    );
                }
            }

            // Publish to the server sent events stream
            let stream = async_stream::stream! {
                let _guard = Guard { state: stream_state, address };
                while let Ok(event) = rx.recv().await {
                    // Must be Infallible here
                    let event_name = event.event_name();
                    let event = Event::default()
                        .event(&event_name)
                        .json_data(event)
                        .unwrap();
                    tracing::trace!("{:#?}", event);
                    yield Ok(event);
                }
            };

            Ok(Sse::new(stream).keep_alive(
                axum::response::sse::KeepAlive::new()
                    .interval(Duration::from_secs(30))
                    .text("keep-alive"),
            ))
        } else {
            Err(status_code)
        }
    } else {
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}
