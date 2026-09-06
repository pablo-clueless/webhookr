//! Svix (also Standard Webhooks): three headers, `svix-id`, `svix-timestamp`,
//! `svix-signature`.
//!
//! The signature value is space-separated versioned entries, each
//! `v1,<base64>`. The signed payload is `{svix-id}.{svix-timestamp}.{raw_body}`.
//!
//! The key is not the secret string: the `whsec_` prefix is stripped and the
//! remainder base64-decoded before use as the HMAC key. Getting this wrong
//! produces digests that look plausible and never match.
//!
//! Tolerance is [`DEFAULT_TOLERANCE_SECS`].

use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};

use super::{
    DEFAULT_TOLERANCE_SECS, SignInput, Signer, Verification, VerifyInput, digests_match,
    hmac_sha256, skew_beyond,
};
use crate::types::Headers;

pub const HEADER_ID: &str = "svix-id";
pub const HEADER_TIMESTAMP: &str = "svix-timestamp";
pub const HEADER_SIGNATURE: &str = "svix-signature";
pub const SECRET_PREFIX: &str = "whsec_";

/// The only version this implements. Entries carrying anything else are skipped.
const VERSION: &str = "v1";

pub struct Svix;

/// Turns a `whsec_...` secret into raw HMAC key bytes.
pub fn decode_secret(secret: &str) -> Result<Vec<u8>> {
    let raw = secret.strip_prefix(SECRET_PREFIX).unwrap_or(secret);
    STANDARD
        .decode(raw)
        .map_err(|e| anyhow::anyhow!("svix secret is not valid base64: {e}"))
}

/// `{id}.{timestamp}.{body}` — over bytes, since the body need not be UTF-8.
fn signed_payload(id: &str, timestamp: &str, body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(id.len() + timestamp.len() + 2 + body.len());
    payload.extend_from_slice(id.as_bytes());
    payload.push(b'.');
    payload.extend_from_slice(timestamp.as_bytes());
    payload.push(b'.');
    payload.extend_from_slice(body);
    payload
}

impl Signer for Svix {
    fn name(&self) -> &'static str {
        "svix"
    }

    fn sign(&self, input: &SignInput<'_>) -> Result<Headers> {
        let key = decode_secret(input.secret)?;
        let id = format!("msg_{}", uuid::Uuid::new_v4().simple());
        let timestamp = input.timestamp.to_string();

        let digest = hmac_sha256(&key, &signed_payload(&id, &timestamp, input.body));

        let mut headers = Headers::new();
        headers.insert(HEADER_ID.into(), id);
        headers.insert(HEADER_TIMESTAMP.into(), timestamp);
        headers.insert(
            HEADER_SIGNATURE.into(),
            format!("{VERSION},{}", STANDARD.encode(digest)),
        );
        Ok(headers)
    }

    fn verify(&self, input: &VerifyInput<'_>) -> Verification {
        let Some(signature) = input.headers.get(HEADER_SIGNATURE) else {
            return Verification::unsigned(format!("no {HEADER_SIGNATURE} header"));
        };
        let (Some(id), Some(timestamp)) = (
            input.headers.get(HEADER_ID),
            input.headers.get(HEADER_TIMESTAMP),
        ) else {
            return Verification::invalid(format!(
                "{HEADER_SIGNATURE} is present without {HEADER_ID} and {HEADER_TIMESTAMP}"
            ));
        };

        let Ok(t) = timestamp.parse::<i64>() else {
            return Verification::invalid(format!(
                "{HEADER_TIMESTAMP} `{timestamp}` is not a unix timestamp"
            ));
        };
        if let Some(skew) = skew_beyond(t, input.now, DEFAULT_TOLERANCE_SECS) {
            return Verification::invalid(format!(
                "timestamp is {}s outside the {DEFAULT_TOLERANCE_SECS}s tolerance",
                skew.abs()
            ));
        }

        let key = match decode_secret(input.secret) {
            Ok(key) => key,
            Err(e) => return Verification::invalid(e.to_string()),
        };
        let digest = hmac_sha256(&key, &signed_payload(id, timestamp, input.body));

        // Space-separated entries; any `v1,` match wins, and other versions are
        // skipped rather than rejected.
        let mut saw_v1 = false;
        for entry in signature.split(' ') {
            let Some(("v1", encoded)) = entry.trim().split_once(',') else {
                continue;
            };
            saw_v1 = true;
            if let Ok(bytes) = STANDARD.decode(encoded)
                && digests_match(&digest, &bytes)
            {
                return Verification::valid();
            }
        }

        if saw_v1 {
            Verification::invalid("no `v1,` digest matches the endpoint secret")
        } else {
            Verification::invalid(format!("{HEADER_SIGNATURE} carries no `v1,` entry"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::tests::FIXTURE_BODY;

    /// base64 of "test_secret_key_" (16 bytes), so decode_secret yields real key bytes.
    const SECRET: &str = "whsec_dGVzdF9zZWNyZXRfa2V5Xw==";
    const NOW: i64 = 1_700_000_000;

    fn signed() -> Headers {
        Svix.sign(&SignInput {
            body: FIXTURE_BODY,
            secret: SECRET,
            timestamp: NOW,
        })
        .unwrap()
    }

    fn verify_at(headers: &Headers, now: i64) -> Verification {
        Svix.verify(&VerifyInput {
            body: FIXTURE_BODY,
            secret: SECRET,
            headers,
            now,
        })
    }

    #[test]
    fn strips_the_prefix_and_base64_decodes_the_key() {
        assert_eq!(decode_secret(SECRET).unwrap(), b"test_secret_key_");
        assert!(decode_secret("whsec_not base64!").is_err());
    }

    #[test]
    fn round_trips_sign_to_verify() {
        let headers = signed();
        assert!(headers.contains_key(HEADER_ID));
        assert!(headers.contains_key(HEADER_TIMESTAMP));
        assert!(headers[HEADER_SIGNATURE].starts_with("v1,"));

        assert_eq!(
            verify_at(&headers, NOW).verdict,
            crate::types::Verdict::Valid
        );
    }

    /// The digest binds the id — the whole point of `{id}.{ts}.{body}`.
    #[test]
    fn a_swapped_message_id_is_invalid() {
        let mut headers = signed();
        headers.insert(HEADER_ID.into(), "msg_somethingelse".into());
        assert_eq!(
            verify_at(&headers, NOW).verdict,
            crate::types::Verdict::Invalid
        );
    }

    #[test]
    fn rejects_a_stale_timestamp_and_names_the_skew() {
        let v = verify_at(&signed(), NOW + DEFAULT_TOLERANCE_SECS + 1);
        assert_eq!(v.verdict, crate::types::Verdict::Invalid);
        assert!(v.detail.unwrap().contains("301"));
    }

    #[test]
    fn skips_unknown_versions_and_accepts_a_later_v1() {
        let headers = signed();
        let mut mixed = headers.clone();
        mixed.insert(
            HEADER_SIGNATURE.into(),
            format!(
                "v0,{} {}",
                STANDARD.encode([0u8; 32]),
                headers[HEADER_SIGNATURE]
            ),
        );
        assert_eq!(verify_at(&mixed, NOW).verdict, crate::types::Verdict::Valid);
    }

    #[test]
    fn a_missing_signature_header_is_unsigned() {
        assert_eq!(
            verify_at(&Headers::new(), NOW).verdict,
            crate::types::Verdict::Unsigned
        );
    }
}
