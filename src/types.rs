//! Shared serde types crossing the REST/SSE boundary.
//!
//! `ui/src/types.ts` mirrors this file field-for-field. Change one, change the
//! other in the same commit — drift here surfaces as silent UI bugs, not errors.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};

/// Header maps are ordered for stable JSON output. Names are lowercased on
/// storage; multi-value headers are joined with `, `.
pub type Headers = BTreeMap<String, String>;

/// Outcome of signature verification at ingress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Digest matched.
    Valid,
    /// A signature header was present and did not match.
    Invalid,
    /// Endpoint has a scheme configured; the request carried no signature header.
    Unsigned,
    /// Endpoint has no scheme configured.
    None,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Valid => "valid",
            Verdict::Invalid => "invalid",
            Verdict::Unsigned => "unsigned",
            Verdict::None => "none",
        }
    }
}

impl std::str::FromStr for Verdict {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "valid" => Verdict::Valid,
            "invalid" => Verdict::Invalid,
            "unsigned" => Verdict::Unsigned,
            "none" => Verdict::None,
            other => anyhow::bail!("unknown verdict {other:?}"),
        })
    }
}

// ---------------------------------------------------------------- endpoints

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub id: String,
    /// The path segment that routes to this endpoint: `/in/{token}`.
    pub token: String,
    pub name: String,
    pub forward_url: Option<String>,
    pub auto_forward: bool,
    /// Signature scheme name, matching the registry in [`crate::sign`].
    pub scheme: Option<String>,
    pub secret: Option<String>,
    pub resp_status: u16,
    pub resp_body: String,
    pub resp_headers: Headers,
    pub resp_delay_ms: u64,
    pub created_at: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateEndpoint {
    pub name: String,
    pub scheme: Option<String>,
    pub secret: Option<String>,
    pub forward_url: Option<String>,
    #[serde(default)]
    pub auto_forward: bool,
}

/// Deserializes a nullable-and-omittable field into a distinguishable pair.
///
/// Without this, serde collapses an explicit `null` and an absent key onto the
/// same `None`, and PATCH loses the ability to *clear* a column — the request
/// is accepted and silently does nothing. Paired with `#[serde(default)]`, an
/// absent key stays `None` while `null` arrives as `Some(None)`.
fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Option::<T>::deserialize(de).map(Some)
}

/// Partial update. `None` leaves the column untouched; nulling a nullable
/// column is expressed as `Some(None)`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PatchEndpoint {
    pub name: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    pub forward_url: Option<Option<String>>,
    pub auto_forward: Option<bool>,
    #[serde(default, deserialize_with = "double_option")]
    pub scheme: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub secret: Option<Option<String>>,
    pub resp_status: Option<u16>,
    pub resp_body: Option<String>,
    pub resp_headers: Option<Headers>,
    pub resp_delay_ms: Option<u64>,
}

// ----------------------------------------------------------------- requests

/// List-row shape. Deliberately carries no body — the list stays cheap even
/// with megabyte payloads in the store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSummary {
    pub id: String,
    pub endpoint_id: String,
    pub method: String,
    pub path: String,
    pub query: String,
    pub remote_addr: Option<String>,
    pub verdict: Verdict,
    pub verdict_detail: Option<String>,
    /// Body length in bytes.
    pub size: u64,
    pub received_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestDetail {
    #[serde(flatten)]
    pub summary: RequestSummary,
    pub headers: Headers,
    /// Base64 of the captured raw bytes. Never a string: a non-UTF-8 body must
    /// survive the trip. Parse for display in the browser, from this field.
    pub body_b64: String,
    pub forwards: Vec<Forward>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RequestQuery {
    pub endpoint_id: Option<String>,
    pub limit: Option<u32>,
    /// Cursor: return requests received strictly before this unix-millis stamp.
    pub before: Option<i64>,
}

// ----------------------------------------------------------------- forwards

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Forward {
    pub id: String,
    pub request_id: String,
    pub target: String,
    pub status: Option<u16>,
    pub duration_ms: Option<i64>,
    pub resp_body_b64: Option<String>,
    pub error: Option<String>,
    pub sent_at: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ReplayRequest {
    /// Overrides the endpoint's `forward_url` for this one replay.
    pub target: Option<String>,
    /// Send the captured bytes and headers verbatim instead of re-signing.
    /// Needed to test that a handler *rejects* stale deliveries.
    #[serde(default)]
    pub preserve_signature: bool,
}

// ------------------------------------------------------------ compose / sign

#[derive(Debug, Clone, Deserialize)]
pub struct ComposeRequest {
    pub target: String,
    pub method: String,
    #[serde(default)]
    pub headers: Headers,
    /// Base64 of the body to send.
    pub body_b64: String,
    pub scheme: Option<String>,
    pub secret: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignRequest {
    /// Base64 of the bytes to sign.
    pub body_b64: String,
    pub scheme: String,
    pub secret: String,
    /// Unix seconds. Defaults to now for schemes that embed a timestamp.
    pub timestamp: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignResponse {
    pub headers: Headers,
}

// ------------------------------------------------------------------- tunnel

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelStatus {
    Up,
    Down,
    Starting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelInfo {
    pub url: Option<String>,
    /// Adapter name, e.g. `cloudflared` or `none`.
    pub adapter: String,
    pub status: TunnelStatus,
}

// -------------------------------------------------------------------- events

/// One SSE frame. The `event:` name is carried alongside by the encoder in
/// [`crate::server::events`]; this is the `data:` payload.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ServerEvent {
    /// `event: request`
    Request { request: RequestSummary },
    /// `event: forward`
    Forward {
        request_id: String,
        forward: Forward,
    },
    /// `event: tunnel`
    Tunnel {
        url: Option<String>,
        status: TunnelStatus,
    },
}

impl ServerEvent {
    /// The SSE `event:` name for this frame.
    pub fn name(&self) -> &'static str {
        match self {
            ServerEvent::Request { .. } => "request",
            ServerEvent::Forward { .. } => "forward",
            ServerEvent::Tunnel { .. } => "tunnel",
        }
    }
}

/// Unix milliseconds.
pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Unix seconds.
pub fn now_secs() -> i64 {
    now_ms() / 1000
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The distinction PATCH depends on: absent means "leave it", `null` means
    /// "clear it". Collapsing the two makes clearing a column impossible.
    #[test]
    fn patch_distinguishes_an_absent_field_from_an_explicit_null() {
        let absent: PatchEndpoint = serde_json::from_str(r#"{"name":"x"}"#).unwrap();
        assert_eq!(absent.name.as_deref(), Some("x"));
        assert!(absent.forward_url.is_none());
        assert!(absent.secret.is_none());

        let nulled: PatchEndpoint =
            serde_json::from_str(r#"{"forward_url":null,"secret":null}"#).unwrap();
        assert_eq!(nulled.forward_url, Some(None));
        assert_eq!(nulled.secret, Some(None));

        let set: PatchEndpoint = serde_json::from_str(r#"{"forward_url":"http://x"}"#).unwrap();
        assert_eq!(set.forward_url, Some(Some("http://x".into())));
    }
}
