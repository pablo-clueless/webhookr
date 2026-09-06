//! Stripe: `stripe-signature: t=<unix_secs>,v1=<hex>`
//!
//! The signed payload is `{t}.{raw_body}` joined with a literal period.
//! Verification tolerance is [`DEFAULT_TOLERANCE_SECS`]; a request outside it is
//! `invalid` with the skew named in the detail.
//!
//! A header may carry several `v1=` entries during a secret rotation — the
//! request is valid if *any* of them matches.

use anyhow::Result;

use super::{
    DEFAULT_TOLERANCE_SECS, SignInput, Signer, Verification, VerifyInput, hex_matches, hmac_sha256,
    skew_beyond,
};
use crate::types::Headers;

pub const HEADER: &str = "stripe-signature";

pub struct Stripe;

/// `{t}.{body}` — built over bytes, never over a `String`, because the body is
/// not necessarily UTF-8 (invariant 1).
fn signed_payload(timestamp: &str, body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(timestamp.len() + 1 + body.len());
    payload.extend_from_slice(timestamp.as_bytes());
    payload.push(b'.');
    payload.extend_from_slice(body);
    payload
}

/// The `t` value and every `v1` value, in header order.
///
/// Unknown keys (`v0`, and whatever Stripe adds next) are ignored rather than
/// rejected, so a future scheme version does not turn every delivery invalid.
fn parse_header(value: &str) -> (Option<&str>, Vec<&str>) {
    let mut timestamp = None;
    let mut v1 = Vec::new();

    for part in value.split(',') {
        match part.trim().split_once('=') {
            Some(("t", v)) => timestamp = Some(v),
            Some(("v1", v)) => v1.push(v),
            _ => {}
        }
    }

    (timestamp, v1)
}

impl Signer for Stripe {
    fn name(&self) -> &'static str {
        "stripe"
    }

    fn sign(&self, input: &SignInput<'_>) -> Result<Headers> {
        let t = input.timestamp.to_string();
        let digest = hmac_sha256(input.secret.as_bytes(), &signed_payload(&t, input.body));

        let mut headers = Headers::new();
        headers.insert(HEADER.into(), format!("t={t},v1={}", hex::encode(digest)));
        Ok(headers)
    }

    fn verify(&self, input: &VerifyInput<'_>) -> Verification {
        let Some(value) = input.headers.get(HEADER) else {
            return Verification::unsigned(format!("no {HEADER} header"));
        };

        let (timestamp, candidates) = parse_header(value);

        let Some(timestamp) = timestamp else {
            return Verification::invalid(format!("{HEADER} carries no `t=` timestamp"));
        };
        let Ok(t) = timestamp.parse::<i64>() else {
            return Verification::invalid(format!("`t={timestamp}` is not a unix timestamp"));
        };

        // Checked before the digest: a replayed-but-correctly-signed delivery is
        // the case this exists to catch, and the skew is the useful detail.
        if let Some(skew) = skew_beyond(t, input.now, DEFAULT_TOLERANCE_SECS) {
            return Verification::invalid(format!(
                "timestamp is {}s outside the {DEFAULT_TOLERANCE_SECS}s tolerance",
                skew.abs()
            ));
        }

        if candidates.is_empty() {
            return Verification::invalid(format!("{HEADER} carries no `v1=` digest"));
        }

        // The timestamp goes back into the payload as the literal string from
        // the header, not as the reparsed integer — `t=0700` must hash as sent.
        let digest = hmac_sha256(
            input.secret.as_bytes(),
            &signed_payload(timestamp, input.body),
        );

        // Any match wins: several v1 entries mean a secret rotation in flight.
        if candidates.iter().any(|c| hex_matches(&digest, c)) {
            Verification::valid()
        } else {
            Verification::invalid("no `v1=` digest matches the endpoint secret")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::tests::FIXTURE_BODY;

    const SECRET: &str = "whsec_test_secret";
    const TIMESTAMP: i64 = 1_700_000_000;
    /// HMAC-SHA256 of `1700000000.{"id":"evt_test","type":"ping"}` under SECRET.
    const EXPECTED_HEX: &str = "76e93d7667b36f8aab799377027b5ad5c17365edfaca34f11cc7c9f570f94a2a";

    fn signed() -> Headers {
        Stripe
            .sign(&SignInput {
                body: FIXTURE_BODY,
                secret: SECRET,
                timestamp: TIMESTAMP,
            })
            .unwrap()
    }

    fn verify_at(headers: &Headers, now: i64) -> Verification {
        Stripe.verify(&VerifyInput {
            body: FIXTURE_BODY,
            secret: SECRET,
            headers,
            now,
        })
    }

    #[test]
    fn reproduces_the_handoff_fixture() {
        assert_eq!(
            signed().get(HEADER).map(String::as_str),
            Some(format!("t={TIMESTAMP},v1={EXPECTED_HEX}").as_str())
        );
    }

    #[test]
    fn round_trips_sign_to_verify() {
        assert_eq!(
            verify_at(&signed(), TIMESTAMP).verdict,
            crate::types::Verdict::Valid
        );
    }

    #[test]
    fn rejects_a_stale_timestamp_and_names_the_skew() {
        let v = verify_at(&signed(), TIMESTAMP + DEFAULT_TOLERANCE_SECS + 1);
        assert_eq!(v.verdict, crate::types::Verdict::Invalid);
        assert!(v.detail.unwrap().contains("301"));
    }

    #[test]
    fn accepts_any_matching_v1_during_a_rotation() {
        let mut headers = Headers::new();
        headers.insert(
            HEADER.into(),
            format!("t={TIMESTAMP},v1={},v1={EXPECTED_HEX}", "00".repeat(32)),
        );
        assert_eq!(
            verify_at(&headers, TIMESTAMP).verdict,
            crate::types::Verdict::Valid
        );
    }

    #[test]
    fn ignores_unknown_scheme_versions() {
        let mut headers = Headers::new();
        headers.insert(
            HEADER.into(),
            format!("t={TIMESTAMP},v0=deadbeef,v1={EXPECTED_HEX}"),
        );
        assert_eq!(
            verify_at(&headers, TIMESTAMP).verdict,
            crate::types::Verdict::Valid
        );
    }

    #[test]
    fn a_header_without_a_digest_is_invalid() {
        let mut headers = Headers::new();
        headers.insert(HEADER.into(), format!("t={TIMESTAMP}"));
        assert_eq!(
            verify_at(&headers, TIMESTAMP).verdict,
            crate::types::Verdict::Invalid
        );
    }
}
