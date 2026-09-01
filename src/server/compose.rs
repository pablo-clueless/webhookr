//! Firing hand-written payloads at arbitrary targets.
//!
//! The composer takes freeform JSON on purpose — v1 ships no provider event
//! catalogue. It signs with the same registry the ingress verifies against, so
//! a payload composed here is indistinguishable from the real provider's.

use axum::{Json, extract::State};

use super::{
    AppState,
    api::{ApiError, ApiResult},
};
use crate::types::{ComposeRequest, Forward, SignRequest, SignResponse};

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
    Json(_body): Json<SignRequest>,
) -> ApiResult<Json<SignResponse>> {
    // TODO(phase 2): resolve the scheme through crate::sign::signer, decode
    // body_b64, and return the produced headers.
    Err(ApiError::bad_request("sign not implemented yet (phase 2)"))
}
