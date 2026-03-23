use crate::server::app::{AppState, ServerEvent};
use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::get;
use axum::Router;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

pub fn routes() -> Router<AppState> {
    Router::new().route("/events", get(event_stream))
}

async fn event_stream(
    State(state): State<AppState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = state.event_tx.subscribe();
    let stream =
        BroadcastStream::new(rx).filter_map(|result: Result<ServerEvent, _>| {
            result.ok().map(|event| {
                let data = serde_json::to_string(&event).unwrap_or_default();
                let event_type = match &event {
                    ServerEvent::ScanStarted { .. } => "scan_started",
                    ServerEvent::ScanCompleted { .. } => "scan_completed",
                    ServerEvent::ScanFailed { .. } => "scan_failed",
                    ServerEvent::ScanProgress { .. } => "scan_progress",
                    ServerEvent::ConfigChanged => "config_changed",
                };
                Ok(Event::default().event(event_type).data(data))
            })
        });

    Sse::new(stream).keep_alive(KeepAlive::default())
}
