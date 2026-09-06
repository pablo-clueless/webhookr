//! Signature schemes — generation and verification through one registry.
//!
//! Both directions share an implementation on purpose: the composer signs with
//! the same code the ingress verifies with, so a scheme cannot drift into
//! "works when we send it, fails when they do".
//!
//! All four schemes are HMAC-SHA256. They differ in which header carries the
//! digest, how it is encoded, and what exactly gets fed to the MAC.

pub mod github;
pub mod hmac_generic;
pub mod stripe;
pub mod svix;

use anyhow::Result;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::types::{Headers, Verdict};

/// Default clock-skew allowance for schemes that embed a timestamp.
pub const DEFAULT_TOLERANCE_SECS: i64 = 300;

/// Everything a scheme needs to produce headers for a payload.
pub struct SignInput<'a> {
    /// The exact bytes that will be sent.
    pub body: &'a [u8],
    pub secret: &'a str,
    /// Unix seconds, for schemes that bind a timestamp into the digest.
    pub timestamp: i64,
}

/// Everything a scheme needs to judge an inbound request.
pub struct VerifyInput<'a> {
    /// The exact bytes as received — never a re-serialized form (invariant 1).
    pub body: &'a [u8],
    pub secret: &'a str,
    /// Inbound headers, names already lowercased.
    pub headers: &'a Headers,
    /// Unix seconds, for the tolerance check.
    pub now: i64,
}

/// A verdict plus the human-readable reason shown in the UI.
pub struct Verification {
    pub verdict: Verdict,
    pub detail: Option<String>,
}

impl Verification {
    pub fn valid() -> Self {
        Self {
            verdict: Verdict::Valid,
            detail: None,
        }
    }

    pub fn invalid(detail: impl Into<String>) -> Self {
        Self {
            verdict: Verdict::Invalid,
            detail: Some(detail.into()),
        }
    }

    /// The endpoint expects a signature and none arrived.
    pub fn unsigned(detail: impl Into<String>) -> Self {
        Self {
            verdict: Verdict::Unsigned,
            detail: Some(detail.into()),
        }
    }
}

pub trait Signer: Send + Sync {
    /// Registry key, and the value stored in `endpoints.scheme`.
    fn name(&self) -> &'static str;

    /// Headers that authenticate `input.body`.
    fn sign(&self, input: &SignInput<'_>) -> Result<Headers>;

    /// Judges an inbound request. Never returns [`Verdict::None`] — that verdict
    /// means "no scheme configured" and is decided before a signer is consulted.
    fn verify(&self, input: &VerifyInput<'_>) -> Verification;
}

/// Looks up a scheme by the name stored on the endpoint.
///
/// `hmac_generic` is configured per-endpoint, so it is resolved through
/// [`hmac_generic::HmacGeneric::from_spec`] rather than this registry.
pub fn signer(name: &str) -> Option<&'static dyn Signer> {
    match name {
        "stripe" => Some(&stripe::Stripe),
        "github" => Some(&github::GitHub),
        "svix" => Some(&svix::Svix),
        _ => None,
    }
}

/// Every scheme name the UI can offer.
pub const SCHEMES: &[&str] = &["stripe", "github", "svix", "hmac_generic"];

/// Builds the signer named by an endpoint's `scheme` column.
///
/// `hmac_generic` carries its per-endpoint configuration inline, after a colon:
///
/// ```text
/// hmac_generic:{"header":"x-sig","encoding":"base64","prefix":"sha256="}
/// ```
///
/// A bare `hmac_generic` takes the defaults. The named schemes are zero-sized,
/// so boxing them costs nothing.
pub fn resolve(scheme: &str) -> Result<Box<dyn Signer>> {
    let (name, spec) = scheme.split_once(':').unwrap_or((scheme, ""));

    Ok(match name.trim() {
        "stripe" => Box::new(stripe::Stripe),
        "github" => Box::new(github::GitHub),
        "svix" => Box::new(svix::Svix),
        "hmac_generic" => Box::new(if spec.trim().is_empty() {
            hmac_generic::HmacGeneric::default()
        } else {
            hmac_generic::HmacGeneric::from_spec(spec)?
        }),
        other => anyhow::bail!("unknown signature scheme {other:?}"),
    })
}

/// The verdict stored against a captured request.
///
/// Misconfiguration on *our* side — a scheme with no secret, or a name that no
/// longer resolves — is [`Verdict::None`] with the reason in the detail, not
/// [`Verdict::Invalid`]. Blaming the sender for our own broken config is the
/// kind of wrong answer that costs an afternoon.
pub fn judge(
    scheme: Option<&str>,
    secret: Option<&str>,
    headers: &Headers,
    body: &[u8],
    now: i64,
) -> Verification {
    let Some(scheme) = scheme.filter(|s| !s.is_empty()) else {
        return Verification {
            verdict: Verdict::None,
            detail: None,
        };
    };

    let Some(secret) = secret.filter(|s| !s.is_empty()) else {
        return Verification {
            verdict: Verdict::None,
            detail: Some(format!("endpoint has scheme `{scheme}` but no secret")),
        };
    };

    let signer = match resolve(scheme) {
        Ok(signer) => signer,
        Err(e) => {
            return Verification {
                verdict: Verdict::None,
                detail: Some(e.to_string()),
            };
        }
    };

    signer.verify(&VerifyInput {
        body,
        secret,
        headers,
        now,
    })
}

// ------------------------------------------------------------------ helpers

/// HMAC-SHA256 of `payload` under `key`.
pub fn hmac_sha256(key: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any length");
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

/// Constant-time digest comparison (invariant 5). Never compare digests with
/// `==` — the early exit leaks the length of the matching prefix.
pub fn digests_match(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Constant-time compare of a computed digest against a hex-encoded candidate.
pub fn hex_matches(expected: &[u8], candidate_hex: &str) -> bool {
    match hex::decode(candidate_hex.trim()) {
        Ok(bytes) => digests_match(expected, &bytes),
        Err(_) => false,
    }
}

/// How far `timestamp` is from `now`, in seconds, if it falls outside
/// `tolerance`. `None` means the request is inside the window.
pub fn skew_beyond(timestamp: i64, now: i64, tolerance: i64) -> Option<i64> {
    let skew = now - timestamp;
    (skew.abs() > tolerance).then_some(skew)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The body every fixture in HANDOFF.md is computed over.
    pub(crate) const FIXTURE_BODY: &[u8] = br#"{"id":"evt_test","type":"ping"}"#;

    #[test]
    fn digest_comparison_is_length_safe() {
        let d = hmac_sha256(b"k", b"v");
        assert!(digests_match(&d, &d));
        assert!(!digests_match(&d, &d[..16]));
        assert!(hex_matches(&d, &hex::encode(d)));
        assert!(!hex_matches(&d, "not hex"));
    }

    #[test]
    fn tolerance_window_is_symmetric() {
        assert_eq!(skew_beyond(1_000, 1_100, 300), None);
        assert_eq!(skew_beyond(1_000, 1_400, 300), Some(400));
        assert_eq!(skew_beyond(1_400, 1_000, 300), Some(-400));
    }

    #[test]
    fn resolve_handles_the_inline_hmac_generic_spec() {
        assert_eq!(resolve("github").unwrap().name(), "github");
        assert_eq!(resolve("hmac_generic").unwrap().name(), "hmac_generic");
        assert_eq!(
            resolve(r#"hmac_generic:{"header":"x-sig","encoding":"base64"}"#)
                .unwrap()
                .name(),
            "hmac_generic"
        );
        assert!(resolve("hmac_generic:not json").is_err());
        assert!(resolve("nope").is_err());
    }

    #[test]
    fn judge_reports_misconfiguration_as_none_not_invalid() {
        let headers = Headers::new();

        // No scheme at all: nothing to say.
        let v = judge(None, None, &headers, FIXTURE_BODY, 0);
        assert_eq!(v.verdict, Verdict::None);
        assert!(v.detail.is_none());

        // Scheme without a secret, and an unknown scheme: both explain themselves.
        for (scheme, secret) in [(Some("github"), None), (Some("nope"), Some("s"))] {
            let v = judge(scheme, secret, &headers, FIXTURE_BODY, 0);
            assert_eq!(v.verdict, Verdict::None);
            assert!(v.detail.is_some());
        }

        // A configured endpoint with no signature header is the sender's gap.
        let v = judge(Some("github"), Some("s"), &headers, FIXTURE_BODY, 0);
        assert_eq!(v.verdict, Verdict::Unsigned);
    }

    #[test]
    fn judge_routes_a_signed_request_to_the_right_scheme() {
        let headers = github::GitHub
            .sign(&SignInput {
                body: FIXTURE_BODY,
                secret: "ghs_test_secret",
                timestamp: 0,
            })
            .unwrap();

        let v = judge(
            Some("github"),
            Some("ghs_test_secret"),
            &headers,
            FIXTURE_BODY,
            0,
        );
        assert_eq!(v.verdict, Verdict::Valid);

        // Right digest, wrong scheme: stripe looks for a header that isn't there.
        let v = judge(
            Some("stripe"),
            Some("ghs_test_secret"),
            &headers,
            FIXTURE_BODY,
            0,
        );
        assert_eq!(v.verdict, Verdict::Unsigned);
    }

    #[test]
    fn registry_resolves_every_named_scheme() {
        for name in SCHEMES {
            // hmac_generic is per-endpoint config, not a registry singleton.
            if *name == "hmac_generic" {
                continue;
            }
            assert_eq!(signer(name).map(|s| s.name()), Some(*name));
        }
        assert!(signer("nope").is_none());
    }
}
