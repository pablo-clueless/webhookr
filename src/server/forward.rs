//! Replaying captured requests at a target.
//!
//! # Header rewriting (invariant 4)
//!
//! Exactly three headers change on the way out; everything else — the signature
//! header included — is passed through verbatim. The whole point of the tool is
//! that the local handler sees what the provider sent.
//!
//! | Header            | Treatment          |
//! | ----------------- | ------------------ |
//! | `host`            | rewritten to the target's host |
//! | `content-length`  | recomputed         |
//! | `accept-encoding` | dropped            |
//!
//! # Re-signing (invariant 7)
//!
//! Replay recomputes the signature with a fresh timestamp whenever the endpoint
//! has a secret. Stripe rejects signatures older than its tolerance window, so
//! replaying a captured `t=` value fails at the receiver every time.
//!
//! `preserve_signature: true` sends the original bytes and headers untouched —
//! which is how you test that your handler *rejects* stale deliveries.

use axum::{
    Json,
    extract::{Path, State},
};

use super::{AppState, api::ApiResult};
use crate::types::{Forward, Headers, ReplayRequest};

/// Headers this module owns. Everything else is forwarded as-is.
pub const REWRITTEN: [&str; 3] = ["host", "content-length", "accept-encoding"];

/// `POST /api/requests/{id}/replay`
pub async fn replay(
    State(_state): State<AppState>,
    Path(_id): Path<String>,
    Json(_body): Json<ReplayRequest>,
) -> ApiResult<Json<Forward>> {
    // TODO(phase 3): load the request's raw body and headers, resolve the
    // target (body.target, else the endpoint's forward_url), re-sign unless
    // body.preserve_signature, send via state.http, record through
    // db::forwards::insert, emit ServerEvent::Forward.
    Err(crate::server::api::ApiError::bad_request(
        "replay not implemented yet (phase 3)",
    ))
}

/// Applies invariant 4 to a captured header map.
///
/// `content-length` is left out entirely — the HTTP client sets it from the
/// body it is actually given, which is the only value that can be correct.
pub fn rewrite_headers(captured: &Headers, target_host: &str) -> Headers {
    let mut out: Headers = captured
        .iter()
        .filter(|(name, _)| !REWRITTEN.contains(&name.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    out.insert("host".into(), target_host.to_owned());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_three_headers_and_passes_the_rest_through() {
        let mut captured = Headers::new();
        captured.insert("host".into(), "tunnel.example.com".into());
        captured.insert("content-length".into(), "999".into());
        captured.insert("accept-encoding".into(), "gzip".into());
        captured.insert("stripe-signature".into(), "t=1,v1=abc".into());
        captured.insert("content-type".into(), "application/json".into());

        let out = rewrite_headers(&captured, "localhost:3000");

        assert_eq!(out.get("host").unwrap(), "localhost:3000");
        assert!(!out.contains_key("content-length"));
        assert!(!out.contains_key("accept-encoding"));
        // The signature survives untouched — that is the point of the tool.
        assert_eq!(out.get("stripe-signature").unwrap(), "t=1,v1=abc");
        assert_eq!(out.get("content-type").unwrap(), "application/json");
    }
}
