//! `GET /api/events` — the server→client half of the transport.
//!
//! SSE rather than WebSocket: the traffic is one-directional, it survives
//! proxies, and `EventSource` reconnects on its own. The client→server half is
//! plain REST.

use std::convert::Infallible;

use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::{Stream, StreamExt};
use tokio_stream::wrappers::BroadcastStream;

use super::AppState;

/// Subscribes to the broadcast channel and re-emits each frame as SSE.
///
/// A client that falls far enough behind is `Lagged` off the channel; those
/// frames are dropped rather than closing the stream, since a dropped row is
/// better than a dead connection and the list can be refetched.
pub async fn stream(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.events.subscribe();

    let stream = BroadcastStream::new(rx).filter_map(|frame| async move {
        let event = match frame {
            Ok(event) => event,
            Err(e) => {
                tracing::warn!(error = %e, "SSE client lagged; dropping frames");
                return None;
            }
        };

        // The `event:` name is what the UI's addEventListener matches on; the
        // payload is the JSON object on the `data:` line.
        Some(Ok(Event::default()
            .event(event.name())
            .json_data(&event)
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "could not serialize an SSE frame");
                Event::default().comment("serialization failed")
            })))
    });

    // Comment pings keep intermediaries from reaping an idle connection.
    Sse::new(stream).keep_alive(KeepAlive::default())
}
