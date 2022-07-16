//! Wrapper for an event source stream that emits change notifications.
use futures::stream::Stream;
use futures::task::{Context, Poll};
use pin_project_lite::pin_project;
use reqwest_eventsource::{Event, EventSource};
use std::pin::Pin;

use sos_core::events::ChangeNotification;

use crate::client::{Error, Result};

/// Enumeration yielded by the changes stream.
pub enum ChangeStreamEvent {
    /// Emitted when the server sent events stream is opened.
    Open,
    /// Emitted when a change notification is received.
    Message(ChangeNotification),
}

pin_project! {
    /// Change stream emits change notifications.
    pub struct ChangeStream {
        #[pin]
        event_source: EventSource,
    }
}

impl ChangeStream {
    /// Create a new change stream.
    pub fn new(event_source: EventSource) -> Self {
        Self { event_source }
    }
}

impl Stream for ChangeStream {
    type Item = Result<ChangeStreamEvent>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        match this.event_source.as_mut().poll_next(cx) {
            Poll::Ready(Some(Err(err))) => {
                this.event_source.close();
                Poll::Ready(Some(Err(Error::from(err))))
            }
            Poll::Ready(Some(Ok(event))) => match event {
                Event::Open => Poll::Ready(Some(Ok(ChangeStreamEvent::Open))),
                Event::Message(message) => {
                    let notification: ChangeNotification =
                        serde_json::from_str(&message.data)?;
                    Poll::Ready(Some(Ok(ChangeStreamEvent::Message(
                        notification,
                    ))))
                }
            },
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
