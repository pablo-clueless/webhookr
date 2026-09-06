//! GitHub: `x-hub-signature-256: sha256=<hex>`
//!
//! The signed payload is the raw body alone — no timestamp, so no tolerance
//! window and no re-signing concern on replay.

use anyhow::Result;

use super::{SignInput, Signer, Verification, VerifyInput, hex_matches, hmac_sha256};
use crate::types::Headers;

pub const HEADER: &str = "x-hub-signature-256";
pub const PREFIX: &str = "sha256=";

pub struct GitHub;

impl Signer for GitHub {
    fn name(&self) -> &'static str {
        "github"
    }

    fn sign(&self, input: &SignInput<'_>) -> Result<Headers> {
        let digest = hmac_sha256(input.secret.as_bytes(), input.body);

        let mut headers = Headers::new();
        headers.insert(HEADER.into(), format!("{PREFIX}{}", hex::encode(digest)));
        Ok(headers)
    }

    fn verify(&self, input: &VerifyInput<'_>) -> Verification {
        let Some(value) = input.headers.get(HEADER) else {
            return Verification::unsigned(format!("no {HEADER} header"));
        };

        // A present-but-malformed header is `invalid`, not `unsigned`: the
        // sender tried to authenticate and got it wrong, which is the thing
        // worth surfacing.
        let Some(candidate) = value.trim().strip_prefix(PREFIX) else {
            return Verification::invalid(format!("{HEADER} is not in `{PREFIX}<hex>` form"));
        };

        let digest = hmac_sha256(input.secret.as_bytes(), input.body);
        if hex_matches(&digest, candidate) {
            Verification::valid()
        } else {
            Verification::invalid("digest does not match the endpoint secret")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::tests::FIXTURE_BODY;

    const SECRET: &str = "ghs_test_secret";
    /// HMAC-SHA256 of the fixture body alone under SECRET.
    const EXPECTED_HEX: &str = "575f31703fceff0bc48b31ddafa528e733869cee105804f38f19b7183c0c6bff";

    fn signed() -> Headers {
        GitHub
            .sign(&SignInput {
                body: FIXTURE_BODY,
                secret: SECRET,
                timestamp: 0,
            })
            .unwrap()
    }

    #[test]
    fn reproduces_the_handoff_fixture() {
        assert_eq!(
            signed().get(HEADER).map(String::as_str),
            Some(format!("{PREFIX}{EXPECTED_HEX}").as_str())
        );
    }

    #[test]
    fn round_trips_sign_to_verify() {
        let v = GitHub.verify(&VerifyInput {
            body: FIXTURE_BODY,
            secret: SECRET,
            headers: &signed(),
            now: 0,
        });
        assert_eq!(v.verdict, crate::types::Verdict::Valid);
    }

    #[test]
    fn one_flipped_character_is_invalid() {
        let mut headers = signed();
        let flipped = format!("{PREFIX}0{}", &EXPECTED_HEX[1..]);
        headers.insert(HEADER.into(), flipped);

        let v = GitHub.verify(&VerifyInput {
            body: FIXTURE_BODY,
            secret: SECRET,
            headers: &headers,
            now: 0,
        });
        assert_eq!(v.verdict, crate::types::Verdict::Invalid);
    }

    #[test]
    fn a_missing_header_is_unsigned_not_invalid() {
        let v = GitHub.verify(&VerifyInput {
            body: FIXTURE_BODY,
            secret: SECRET,
            headers: &Headers::new(),
            now: 0,
        });
        assert_eq!(v.verdict, crate::types::Verdict::Unsigned);
    }
}
