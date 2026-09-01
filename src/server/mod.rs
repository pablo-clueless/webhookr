//! HTTP surface: ingress catch-all, REST API, SSE, and the embedded UI.

pub mod api;
pub mod compose;
pub mod events;
pub mod forward;
pub mod ingress;

use std::sync::Arc;

use anyhow::Result;
use axum::Router;
use tokio::sync::{RwLock, broadcast};

use crate::{db::Db, tunnel::TunnelState, types::ServerEvent};

/// Vite's dev server, proxied to in debug builds. See [`ui`].
pub const VITE_DEV_URL: &str = "http://127.0.0.1:5173";

/// Shared across every handler. Cheap to clone.
#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    /// Fan-out to every connected SSE client. Send errors mean "no listeners",
    /// which is normal and never fatal.
    pub events: broadcast::Sender<ServerEvent>,
    /// The forwarding client. Built once — see [`forwarding_client`].
    pub http: reqwest::Client,
    pub tunnel: Arc<RwLock<TunnelState>>,
}

impl AppState {
    pub fn new(db: Db, tunnel: TunnelState) -> Result<Self> {
        let (events, _) = broadcast::channel(256);
        Ok(Self {
            db,
            events,
            http: forwarding_client()?,
            tunnel: Arc::new(RwLock::new(tunnel)),
        })
    }

    /// Publishes an SSE frame. A closed channel just means nobody is watching.
    pub fn emit(&self, event: ServerEvent) {
        let _ = self.events.send(event);
    }
}

/// The client used for forwarding, replay, and compose.
///
/// Invariant 3: automatic decompression must be off. This build goes further
/// than disabling it — the `gzip`, `brotli`, `deflate`, and `zstd` features are
/// not enabled on `reqwest` at all, so the decompression path does not exist.
/// If you ever turn one of those features on, you must add the matching
/// `.no_gzip()` / `.no_brotli()` / `.no_deflate()` call here, or a compressed
/// inbound body will be silently inflated and the forwarded bytes will stop
/// matching the captured ones.
///
/// Redirects are off too: a 302 from the target is a result worth showing, not
/// something to chase.
pub fn forwarding_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()?)
}

/// Assembles the full application.
///
/// Route order matters: `/api` and `/in` are matched first, and everything else
/// falls through to the UI so client-side routes survive a page reload.
pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(api::router())
        .merge(ingress::router())
        .fallback(ui::handler)
        .with_state(state)
}

/// UI delivery.
///
/// Debug builds proxy to the Vite dev server so HMR works against a live
/// backend. Release builds serve [`rust_embed`]-baked assets out of `dist-ui/`,
/// which is what makes the shipped artifact a single binary.
pub mod ui {
    use axum::{
        body::Body,
        extract::State,
        http::{StatusCode, Uri, header},
        response::{IntoResponse, Response},
    };

    use super::AppState;

    #[derive(rust_embed::Embed)]
    #[folder = "dist-ui/"]
    struct Assets;

    pub async fn handler(State(state): State<AppState>, uri: Uri) -> Response {
        if cfg!(debug_assertions) {
            proxy_to_vite(&state, &uri).await
        } else {
            serve_embedded(uri.path())
        }
    }

    /// Serves a baked asset, falling back to `index.html` so the SPA can handle
    /// unknown paths itself.
    fn serve_embedded(path: &str) -> Response {
        let path = path.trim_start_matches('/');
        let candidate = if path.is_empty() { "index.html" } else { path };

        let (file, name) = match Assets::get(candidate) {
            Some(f) => (f, candidate),
            None => match Assets::get("index.html") {
                Some(f) => (f, "index.html"),
                None => {
                    return (
                        StatusCode::NOT_FOUND,
                        "UI assets are not built. Run `npm --prefix ui run build`.",
                    )
                        .into_response();
                }
            },
        };

        let mime = mime_guess::from_path(name).first_or_octet_stream();
        (
            [(header::CONTENT_TYPE, mime.as_ref())],
            file.data.into_owned(),
        )
            .into_response()
    }

    async fn proxy_to_vite(state: &AppState, uri: &Uri) -> Response {
        let target = format!(
            "{}{}",
            super::VITE_DEV_URL,
            uri.path_and_query().map(|p| p.as_str()).unwrap_or("/")
        );

        match state.http.get(&target).send().await {
            Ok(resp) => {
                let status = resp.status();
                let content_type = resp
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("text/html")
                    .to_owned();

                match resp.bytes().await {
                    Ok(body) => (
                        status,
                        [(header::CONTENT_TYPE, content_type)],
                        Body::from(body),
                    )
                        .into_response(),
                    Err(e) => bad_gateway(&e.to_string()),
                }
            }
            Err(e) => bad_gateway(&e.to_string()),
        }
    }

    fn bad_gateway(err: &str) -> Response {
        (
            StatusCode::BAD_GATEWAY,
            format!(
                "The UI dev server is not reachable at {}.\n\
                 Start it with `npm --prefix ui run dev`.\n\n{err}",
                super::VITE_DEV_URL
            ),
        )
            .into_response()
    }
}
