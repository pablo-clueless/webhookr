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

use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::any,
};

use super::AppState;
use crate::types::Headers;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/in/{*path}", any(capture))
        .route("/in/", any(capture_root))
        .route("/in", any(capture_root))
}

/// Captures a delivery. Always answers with the endpoint's configured response;
/// never 4xx on a body it could not parse.
async fn capture(
    State(_state): State<AppState>,
    Path(path): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (token, rest) = split_token(&path);
    let _ = (
        token,
        rest,
        method,
        uri.query().unwrap_or(""),
        headers,
        body,
    );

    // TODO(phase 1): resolve the token to an endpoint (404 if unknown), flatten
    // the headers with `flatten_headers`, compute the verdict via crate::sign,
    // insert through db::requests::insert, emit ServerEvent::Request, honour
    // resp_delay_ms, and reply with the endpoint's configured status/body/headers.
    // TODO(phase 3): when the endpoint has auto_forward, spawn the forward.
    StatusCode::OK.into_response()
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
