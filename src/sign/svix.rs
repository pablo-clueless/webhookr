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

use anyhow::{Result, bail};

use super::{DEFAULT_TOLERANCE_SECS, SignInput, Signer, Verification, VerifyInput};
use crate::types::Headers;

pub const HEADER_ID: &str = "svix-id";
pub const HEADER_TIMESTAMP: &str = "svix-timestamp";
pub const HEADER_SIGNATURE: &str = "svix-signature";
pub const SECRET_PREFIX: &str = "whsec_";

pub struct Svix;

/// Turns a `whsec_...` secret into raw HMAC key bytes.
pub fn decode_secret(secret: &str) -> Result<Vec<u8>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let raw = secret.strip_prefix(SECRET_PREFIX).unwrap_or(secret);
    STANDARD
        .decode(raw)
        .map_err(|e| anyhow::anyhow!("svix secret is not valid base64: {e}"))
}

impl Signer for Svix {
    fn name(&self) -> &'static str {
        "svix"
    }

    fn sign(&self, _input: &SignInput<'_>) -> Result<Headers> {
        // TODO(phase 2): generate a msg id, sign `{id}.{ts}.{body}` with
        // decode_secret(secret), emit all three headers with `v1,<base64>`.
        bail!("svix signer not implemented yet (phase 2)")
    }

    fn verify(&self, _input: &VerifyInput<'_>) -> Verification {
        // TODO(phase 2): split HEADER_SIGNATURE on ' ', keep the `v1,` entries,
        // check skew against DEFAULT_TOLERANCE_SECS, constant-time compare.
        let _ = DEFAULT_TOLERANCE_SECS;
        Verification::invalid("svix verification not implemented yet (phase 2)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::tests::FIXTURE_BODY;

    /// base64 of "test_secret_key_" (16 bytes), so decode_secret yields real key bytes.
    const SECRET: &str = "whsec_dGVzdF9zZWNyZXRfa2V5Xw==";

    #[test]
    fn strips_the_prefix_and_base64_decodes_the_key() {
        assert_eq!(decode_secret(SECRET).unwrap(), b"test_secret_key_");
        assert!(decode_secret("whsec_not base64!").is_err());
    }

    #[test]
    #[ignore = "phase 2"]
    fn round_trips_sign_to_verify() {
        let now = 1_700_000_000;
        let headers = Svix
            .sign(&SignInput {
                body: FIXTURE_BODY,
                secret: SECRET,
                timestamp: now,
            })
            .unwrap();
        assert!(headers.contains_key(HEADER_ID));
        assert!(headers.contains_key(HEADER_TIMESTAMP));

        let v = Svix.verify(&VerifyInput {
            body: FIXTURE_BODY,
            secret: SECRET,
            headers: &headers,
            now,
        });
        assert_eq!(v.verdict, crate::types::Verdict::Valid);
    }
}
