//! Wrapper for an event source stream that emits change notifications.
use std::pin::Pin;
use reqwest_eventsource::{EventSource, Event};
use pin_project_lite::pin_project;
use futures::task::{Poll, Context};
use futures::stream::Stream;

use sos_core::events::ChangeNotification;

use crate::client::{Error, Result};

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
    type Item = Result<ChangeNotification>;

    fn poll_next(
        self: Pin<&mut Self>, 
        cx: &mut Context<'_>
    ) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        match this.event_source.as_mut().poll_next(cx)
        {
            Poll::Ready(Some(Err(err))) => {
                this.event_source.close();
                Poll::Ready(Some(Err(Error::from(err))))
            }
            Poll::Ready(Some(Ok(event))) => {
                match event {
                    Event::Open => Poll::Pending,
                    Event::Message(message) => {
                        let notification: ChangeNotification =
                            serde_json::from_str(&message.data)?;
                        Poll::Ready(Some(Ok(notification)))
                    }
                }
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
