//! A config-driven catch-all for providers that just HMAC the body.
//!
//! Unlike the named schemes this one is not a registry singleton — the header
//! name, digest encoding, and optional value prefix come from the endpoint's
//! configuration. The signed payload is always the raw body alone.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::{SignInput, Signer, Verification, VerifyInput};
use crate::types::Headers;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    #[default]
    Hex,
    Base64,
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

    fn sign(&self, _input: &SignInput<'_>) -> Result<Headers> {
        // TODO(phase 2): hmac_sha256(secret, body), encode per self.encoding,
        // emit `self.header: {prefix}{digest}`.
        bail!("hmac_generic signer not implemented yet (phase 2)")
    }

    fn verify(&self, _input: &VerifyInput<'_>) -> Verification {
        // TODO(phase 2): read self.header, strip self.prefix, decode per
        // self.encoding, constant-time compare.
        Verification::invalid("hmac_generic verification not implemented yet (phase 2)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
