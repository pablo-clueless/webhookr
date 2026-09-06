//! The catch-all that captures inbound webhooks: `/in/{token}/{rest...}`.
//!
//! # Extractor rules
//!
//! **Invariant 2: never use `Json<T>` here.** It consumes the body and rejects
//! anything that is not JSON. Ingress must accept every content type, including
//! empty bodies and `application/x-www-form-urlencoded` — a provider's
//! malformed payload is exactly the thing a developer is here to inspect, so it
//! has to be captured, not rejected.
//!
//! **Invariant 1: the body is [`Bytes`] from arrival to storage.** It goes to
//! SQLite as a BLOB and back out to the target unchanged. Nothing on this path
//! may deserialize and re-serialize it: a `serde_json` round-trip reorders keys
//! and normalizes whitespace, which changes the HMAC digest — and only for
//! *some* payloads, so it presents as flakiness rather than a bug.
//!
//! `Bytes` is declared last in the handler signature because it consumes the
//! request body.

use std::{net::SocketAddr, time::Duration};

use axum::{
    Router,
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::any,
};

use super::AppState;
use crate::{
    db::{endpoints, requests},
    types::{Endpoint, Headers, ServerEvent},
};

/// Providers send big payloads — a truncated capture is worse than a slow one,
/// and axum's 2 MiB default would reject them with no trace in the store.
const MAX_BODY_BYTES: usize = 25 * 1024 * 1024;

/// Ceiling on `resp_delay_ms`, so a mistyped config cannot wedge every delivery.
const MAX_RESP_DELAY: Duration = Duration::from_secs(30);

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/in/{*path}", any(capture))
        .route("/in/", any(capture_root))
        .route("/in", any(capture_root))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

/// Captures a delivery. Always answers with the endpoint's configured response;
/// never 4xx on a body it could not parse.
async fn capture(
    State(state): State<AppState>,
    Path(path): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (token, rest) = split_token(&path);

    let token = token.to_owned();
    let endpoint = match state.db.call(move |c| endpoints::by_token(c, &token)).await {
        Ok(Some(endpoint)) => endpoint,
        Ok(None) => return unknown_token(),
        Err(e) => {
            tracing::error!(error = %e, "could not resolve the endpoint token");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let headers = flatten_headers(&headers);
    let remote = remote_addr(&headers, peer);

    // Verdict before storage: it is a property of the bytes as they arrived, and
    // recomputing it later against a rotated secret would rewrite history.
    let verification = crate::sign::judge(
        endpoint.scheme.as_deref(),
        endpoint.secret.as_deref(),
        &headers,
        &body,
        crate::types::now_secs(),
    );

    let new = requests::NewRequest {
        endpoint_id: endpoint.id.clone(),
        method: method.to_string(),
        // Normalised with a leading slash so the forwarder can join it onto the
        // target without re-deriving it.
        path: format!("/{}", rest.trim_start_matches('/')),
        query: uri.query().unwrap_or("").to_owned(),
        headers,
        // Invariant 1: the same bytes that arrived, straight to the BLOB.
        body: body.to_vec(),
        remote_addr: Some(remote),
        verdict: verification.verdict,
        verdict_detail: verification.detail,
    };

    let summary = match state.db.call(move |c| requests::insert(c, new)).await {
        Ok(summary) => summary,
        Err(e) => {
            tracing::error!(error = %e, "could not store a captured request");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    tracing::info!(
        id = %summary.id,
        method = %summary.method,
        path = %summary.path,
        verdict = summary.verdict.as_str(),
        size = summary.size,
        "captured"
    );

    state.emit(ServerEvent::Request {
        request: summary.clone(),
    });

    // TODO(phase 3): when the endpoint has auto_forward, spawn the forward.

    respond_as_configured(&endpoint).await
}

/// The peer address, preferring `x-forwarded-for` — behind a tunnel the socket
/// is always the local `cloudflared` process, which tells you nothing.
fn remote_addr(headers: &Headers, peer: SocketAddr) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| peer.to_string())
}

/// Replays the endpoint's canned response: delay, status, headers, then body.
async fn respond_as_configured(endpoint: &Endpoint) -> Response {
    if endpoint.resp_delay_ms > 0 {
        let delay = Duration::from_millis(endpoint.resp_delay_ms).min(MAX_RESP_DELAY);
        tokio::time::sleep(delay).await;
    }

    let status =
        StatusCode::from_u16(endpoint.resp_status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut headers = HeaderMap::new();
    for (name, value) in &endpoint.resp_headers {
        // A header the user typed by hand can be unrepresentable; skip it rather
        // than failing a delivery that was otherwise captured fine.
        match (
            HeaderName::try_from(name.as_str()),
            HeaderValue::try_from(value.as_str()),
        ) {
            (Ok(name), Ok(value)) => {
                headers.insert(name, value);
            }
            _ => tracing::warn!(name, "skipping an unrepresentable response header"),
        }
    }

    // Only defaulted, never forced: an endpoint configured to answer XML should.
    if !headers.contains_key(header::CONTENT_TYPE) && !endpoint.resp_body.is_empty() {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    }

    (status, headers, endpoint.resp_body.clone()).into_response()
}

fn unknown_token() -> Response {
    (
        StatusCode::NOT_FOUND,
        "No endpoint with that token. Check the URL against the endpoint list.",
    )
        .into_response()
}

/// `/in` with no token at all — answered with a hint rather than a bare 404.
async fn capture_root() -> Response {
    (
        StatusCode::NOT_FOUND,
        "No endpoint token in the path. Deliver to /in/{token}.",
    )
        .into_response()
}

/// Splits `8f2ac1/orders/created` into the token and the trailing path.
///
/// The trailing path is preserved so a provider configured against
/// `{tunnel}/in/{token}/orders/created` forwards to the same sub-path on the
/// local target.
fn split_token(path: &str) -> (&str, &str) {
    match path.split_once('/') {
        Some((token, rest)) => (token, rest),
        None => (path, ""),
    }
}

/// Header names lowercased, multi-value headers joined with `, `.
///
/// Non-UTF-8 header values are dropped rather than lossily converted — a
/// mangled value in the store would be worse than a missing one.
pub fn flatten_headers(headers: &HeaderMap) -> Headers {
    let mut out = Headers::new();
    for (name, value) in headers {
        let Ok(value) = value.to_str() else { continue };
        out.entry(name.as_str().to_ascii_lowercase())
            .and_modify(|existing| {
                existing.push_str(", ");
                existing.push_str(value);
            })
            .or_insert_with(|| value.to_owned());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderName, HeaderValue};

    #[test]
    fn splits_the_token_from_the_trailing_path() {
        assert_eq!(split_token("8f2ac1"), ("8f2ac1", ""));
        assert_eq!(split_token("8f2ac1/orders"), ("8f2ac1", "orders"));
        assert_eq!(
            split_token("8f2ac1/orders/created"),
            ("8f2ac1", "orders/created")
        );
    }

    #[test]
    fn lowercases_names_and_joins_repeats() {
        let mut headers = HeaderMap::new();
        headers.append(
            HeaderName::from_static("x-thing"),
            HeaderValue::from_static("a"),
        );
        headers.append(
            HeaderName::from_static("x-thing"),
            HeaderValue::from_static("b"),
        );
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );

        let flat = flatten_headers(&headers);
        assert_eq!(flat.get("x-thing").unwrap(), "a, b");
        assert_eq!(flat.get("content-type").unwrap(), "application/json");
    }
}
