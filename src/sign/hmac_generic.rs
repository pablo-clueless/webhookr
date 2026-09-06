//! A config-driven catch-all for providers that just HMAC the body.
//!
//! Unlike the named schemes this one is not a registry singleton — the header
//! name, digest encoding, and optional value prefix come from the endpoint's
//! configuration. The signed payload is always the raw body alone.

use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use super::{SignInput, Signer, Verification, VerifyInput, digests_match, hmac_sha256};
use crate::types::Headers;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    #[default]
    Hex,
    Base64,
}

impl Encoding {
    fn encode(self, digest: &[u8]) -> String {
        match self {
            Encoding::Hex => hex::encode(digest),
            Encoding::Base64 => STANDARD.encode(digest),
        }
    }

    fn decode(self, s: &str) -> Option<Vec<u8>> {
        match self {
            Encoding::Hex => hex::decode(s).ok(),
            Encoding::Base64 => STANDARD.decode(s).ok(),
        }
    }
}

/// Stored on the endpoint alongside `scheme = "hmac_generic"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HmacGeneric {
    /// Lowercase header name carrying the digest.
    pub header: String,
    #[serde(default)]
    pub encoding: Encoding,
    /// Literal text before the digest, e.g. `sha256=`. Empty for none.
    #[serde(default)]
    pub prefix: String,
}

impl HmacGeneric {
    /// Parses the JSON blob an endpoint stores for this scheme.
    pub fn from_spec(spec: &str) -> Result<Self> {
        serde_json::from_str(spec)
            .map_err(|e| anyhow::anyhow!("invalid hmac_generic configuration: {e}"))
    }

    /// Stored headers are lowercased at capture, so the configured name has to
    /// be matched the same way or a `X-Signature` config silently never fires.
    fn lookup<'a>(&self, headers: &'a Headers) -> Option<&'a String> {
        headers.get(&self.header.to_ascii_lowercase())
    }
}

impl Default for HmacGeneric {
    fn default() -> Self {
        Self {
            header: "x-signature".into(),
            encoding: Encoding::Hex,
            prefix: String::new(),
        }
    }
}

impl Signer for HmacGeneric {
    fn name(&self) -> &'static str {
        "hmac_generic"
    }

    fn sign(&self, input: &SignInput<'_>) -> Result<Headers> {
        let digest = hmac_sha256(input.secret.as_bytes(), input.body);

        let mut headers = Headers::new();
        headers.insert(
            self.header.to_ascii_lowercase(),
            format!("{}{}", self.prefix, self.encoding.encode(&digest)),
        );
        Ok(headers)
    }

    fn verify(&self, input: &VerifyInput<'_>) -> Verification {
        let Some(value) = self.lookup(input.headers) else {
            return Verification::unsigned(format!("no {} header", self.header));
        };

        let value = value.trim();
        let Some(candidate) = value.strip_prefix(self.prefix.as_str()) else {
            return Verification::invalid(format!(
                "{} does not start with `{}`",
                self.header, self.prefix
            ));
        };

        let Some(bytes) = self.encoding.decode(candidate) else {
            return Verification::invalid(format!(
                "{} is not valid {:?}",
                self.header, self.encoding
            ));
        };

        let digest = hmac_sha256(input.secret.as_bytes(), input.body);
        if digests_match(&digest, &bytes) {
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

    const SECRET: &str = "generic_test_secret";

    fn round_trip(cfg: HmacGeneric) -> Verification {
        let headers = cfg
            .sign(&SignInput {
                body: FIXTURE_BODY,
                secret: SECRET,
                timestamp: 0,
            })
            .unwrap();
        cfg.verify(&VerifyInput {
            body: FIXTURE_BODY,
            secret: SECRET,
            headers: &headers,
            now: 0,
        })
    }

    #[test]
    fn parses_a_spec_and_defaults_the_optional_fields() {
        let cfg = HmacGeneric::from_spec(r#"{"header":"x-my-sig"}"#).unwrap();
        assert_eq!(cfg.header, "x-my-sig");
        assert_eq!(cfg.encoding, Encoding::Hex);
        assert_eq!(cfg.prefix, "");

        let cfg = HmacGeneric::from_spec(
            r#"{"header":"x-my-sig","encoding":"base64","prefix":"sha256="}"#,
        )
        .unwrap();
        assert_eq!(cfg.encoding, Encoding::Base64);
        assert_eq!(cfg.prefix, "sha256=");
    }

    #[test]
    fn round_trips_hex_and_base64_with_and_without_a_prefix() {
        for cfg in [
            HmacGeneric::default(),
            HmacGeneric {
                header: "x-my-sig".into(),
                encoding: Encoding::Base64,
                prefix: "sha256=".into(),
            },
        ] {
            assert_eq!(round_trip(cfg).verdict, crate::types::Verdict::Valid);
        }
    }

    /// The signed payload is the body alone, so a hex/no-prefix config must
    /// reproduce the GitHub digest — the two schemes differ only in packaging.
    #[test]
    fn matches_the_github_digest_for_the_same_body_and_secret() {
        let cfg = HmacGeneric {
            header: "x-hub-signature-256".into(),
            encoding: Encoding::Hex,
            prefix: "sha256=".into(),
        };
        let mine = cfg
            .sign(&SignInput {
                body: FIXTURE_BODY,
                secret: "ghs_test_secret",
                timestamp: 0,
            })
            .unwrap();
        let theirs = crate::sign::github::GitHub
            .sign(&SignInput {
                body: FIXTURE_BODY,
                secret: "ghs_test_secret",
                timestamp: 0,
            })
            .unwrap();
        assert_eq!(mine, theirs);
    }

    #[test]
    fn the_configured_header_is_matched_case_insensitively() {
        let cfg = HmacGeneric {
            header: "X-Signature".into(),
            ..Default::default()
        };
        assert_eq!(round_trip(cfg).verdict, crate::types::Verdict::Valid);
    }

    #[test]
    fn a_missing_header_is_unsigned_not_invalid() {
        let v = HmacGeneric::default().verify(&VerifyInput {
            body: FIXTURE_BODY,
            secret: SECRET,
            headers: &Headers::new(),
            now: 0,
        });
        assert_eq!(v.verdict, crate::types::Verdict::Unsigned);
    }
}
