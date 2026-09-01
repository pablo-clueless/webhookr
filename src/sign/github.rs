//! GitHub: `x-hub-signature-256: sha256=<hex>`
//!
//! The signed payload is the raw body alone — no timestamp, so no tolerance
//! window and no re-signing concern on replay.

use anyhow::{Result, bail};

use super::{SignInput, Signer, Verification, VerifyInput};
use crate::types::Headers;

pub const HEADER: &str = "x-hub-signature-256";
pub const PREFIX: &str = "sha256=";

pub struct GitHub;

impl Signer for GitHub {
    fn name(&self) -> &'static str {
        "github"
    }

    fn sign(&self, _input: &SignInput<'_>) -> Result<Headers> {
        // TODO(phase 2): hmac_sha256(secret, body), hex, prefixed with `sha256=`.
        bail!("github signer not implemented yet (phase 2)")
    }

    fn verify(&self, _input: &VerifyInput<'_>) -> Verification {
        // TODO(phase 2): strip PREFIX, then hex_matches against the computed digest.
        Verification::invalid("github verification not implemented yet (phase 2)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::tests::FIXTURE_BODY;

    const SECRET: &str = "ghs_test_secret";
    /// HMAC-SHA256 of the fixture body alone under SECRET.
    const EXPECTED_HEX: &str = "575f31703fceff0bc48b31ddafa528e733869cee105804f38f19b7183c0c6bff";

    #[test]
    #[ignore = "phase 2"]
    fn reproduces_the_handoff_fixture() {
        let headers = GitHub
            .sign(&SignInput {
                body: FIXTURE_BODY,
                secret: SECRET,
                timestamp: 0,
            })
            .unwrap();
        assert_eq!(
            headers.get(HEADER).map(String::as_str),
            Some(format!("{PREFIX}{EXPECTED_HEX}").as_str())
        );
    }

    #[test]
    #[ignore = "phase 2"]
    fn round_trips_sign_to_verify() {
        let headers = GitHub
            .sign(&SignInput {
                body: FIXTURE_BODY,
                secret: SECRET,
                timestamp: 0,
            })
            .unwrap();
        let v = GitHub.verify(&VerifyInput {
            body: FIXTURE_BODY,
            secret: SECRET,
            headers: &headers,
            now: 0,
        });
        assert_eq!(v.verdict, crate::types::Verdict::Valid);
    }
}
