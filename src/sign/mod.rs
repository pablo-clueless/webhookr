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
