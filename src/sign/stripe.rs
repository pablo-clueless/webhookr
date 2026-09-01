//! Stripe: `stripe-signature: t=<unix_secs>,v1=<hex>`
//!
//! The signed payload is `{t}.{raw_body}` joined with a literal period.
//! Verification tolerance is [`DEFAULT_TOLERANCE_SECS`]; a request outside it is
//! `invalid` with the skew named in the detail.
//!
//! A header may carry several `v1=` entries during a secret rotation — the
//! request is valid if *any* of them matches.

use anyhow::{Result, bail};

use super::{DEFAULT_TOLERANCE_SECS, SignInput, Signer, Verification, VerifyInput};
use crate::types::Headers;

pub const HEADER: &str = "stripe-signature";

pub struct Stripe;

impl Signer for Stripe {
    fn name(&self) -> &'static str {
        "stripe"
    }

    fn sign(&self, _input: &SignInput<'_>) -> Result<Headers> {
        // TODO(phase 2): signed payload is `format!("{t}.{body}")`, digest hex,
        // header value `t={t},v1={hex}`.
        bail!("stripe signer not implemented yet (phase 2)")
    }

    fn verify(&self, _input: &VerifyInput<'_>) -> Verification {
        // TODO(phase 2): split the header on ',', collect `t` and every `v1`,
        // reject on skew > DEFAULT_TOLERANCE_SECS, then constant-time compare.
        let _ = DEFAULT_TOLERANCE_SECS;
        Verification::invalid("stripe verification not implemented yet (phase 2)")
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

    #[test]
    #[ignore = "phase 2"]
    fn reproduces_the_handoff_fixture() {
        let headers = Stripe
            .sign(&SignInput {
                body: FIXTURE_BODY,
                secret: SECRET,
                timestamp: TIMESTAMP,
            })
            .unwrap();
        assert_eq!(
            headers.get(HEADER).map(String::as_str),
            Some(format!("t={TIMESTAMP},v1={EXPECTED_HEX}").as_str())
        );
    }

    #[test]
    #[ignore = "phase 2"]
    fn round_trips_sign_to_verify() {
        let headers = Stripe
            .sign(&SignInput {
                body: FIXTURE_BODY,
                secret: SECRET,
                timestamp: TIMESTAMP,
            })
            .unwrap();
        let v = Stripe.verify(&VerifyInput {
            body: FIXTURE_BODY,
            secret: SECRET,
            headers: &headers,
            now: TIMESTAMP,
        });
        assert_eq!(v.verdict, crate::types::Verdict::Valid);
    }

    #[test]
    #[ignore = "phase 2"]
    fn rejects_a_stale_timestamp_and_names_the_skew() {
        let headers = Stripe
            .sign(&SignInput {
                body: FIXTURE_BODY,
                secret: SECRET,
                timestamp: TIMESTAMP,
            })
            .unwrap();
        let v = Stripe.verify(&VerifyInput {
            body: FIXTURE_BODY,
            secret: SECRET,
            headers: &headers,
            now: TIMESTAMP + DEFAULT_TOLERANCE_SECS + 1,
        });
        assert_eq!(v.verdict, crate::types::Verdict::Invalid);
        assert!(v.detail.unwrap().contains("301"));
    }
}
