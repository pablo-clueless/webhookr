//! Firing hand-written payloads at arbitrary targets.
//!
//! The composer takes freeform JSON on purpose — v1 ships no provider event
//! catalogue. It signs with the same registry the ingress verifies against, so
//! a payload composed here is indistinguishable from the real provider's.

use axum::{Json, extract::State};
use base64::{Engine, engine::general_purpose::STANDARD};

use super::{
    AppState,
    api::{ApiError, ApiResult},
};
use crate::{
    sign::{SignInput, resolve},
    types::{ComposeRequest, Forward, SignRequest, SignResponse, now_secs},
};

/// `POST /api/compose` — sign (optionally) and send, recording a [`Forward`].
pub async fn compose(
    State(_state): State<AppState>,
    Json(_body): Json<ComposeRequest>,
) -> ApiResult<Json<Forward>> {
    // TODO(phase 5): base64-decode body_b64, sign when scheme+secret are given,
    // send via state.http, record the attempt, emit ServerEvent::Forward.
    Err(ApiError::bad_request(
        "compose not implemented yet (phase 5)",
    ))
}

/// `POST /api/sign` — headers only, nothing is sent.
///
/// Lets the UI show exactly what a provider would put on the wire, and lets a
/// developer paste those headers into curl.
pub async fn sign(
    State(_state): State<AppState>,
    Json(body): Json<SignRequest>,
) -> ApiResult<Json<SignResponse>> {
    let headers = sign_headers(&body).map_err(ApiError::from)?;
    Ok(Json(SignResponse { headers }))
}

/// The signing half of both `/api/sign` and `/api/compose`.
///
/// Kept separate so the composer signs the exact bytes it is about to send,
/// rather than re-deriving them from a second decode.
pub fn sign_headers(req: &SignRequest) -> anyhow::Result<crate::types::Headers> {
    let body = STANDARD
        .decode(&req.body_b64)
        .map_err(|e| anyhow::anyhow!("body_b64 is not valid base64: {e}"))?;

    let signer = resolve(&req.scheme)?;

    // Defaulting to now is what makes a composed payload pass a live receiver's
    // tolerance check without the caller having to think about clocks.
    signer.sign(&SignInput {
        body: &body,
        secret: &req.secret,
        timestamp: req.timestamp.unwrap_or_else(now_secs),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(scheme: &str, secret: &str) -> SignRequest {
        SignRequest {
            body_b64: STANDARD.encode(br#"{"id":"evt_test","type":"ping"}"#),
            scheme: scheme.into(),
            secret: secret.into(),
            timestamp: Some(1_700_000_000),
        }
    }

    #[test]
    fn signs_through_the_same_registry_the_ingress_verifies_with() {
        let headers = sign_headers(&request("stripe", "whsec_test_secret")).unwrap();
        assert_eq!(
            headers.get("stripe-signature").map(String::as_str),
            Some(
                "t=1700000000,v1=76e93d7667b36f8aab799377027b5ad5c17365edfaca34f11cc7c9f570f94a2a"
            )
        );
    }

    #[test]
    fn rejects_a_bad_body_or_an_unknown_scheme() {
        let mut bad_body = request("github", "s");
        bad_body.body_b64 = "not base64!".into();
        assert!(sign_headers(&bad_body).is_err());

        assert!(sign_headers(&request("nope", "s")).is_err());
    }
}
