//! The REST surface under `/api`.
//!
//! Bodies cross this boundary base64-encoded in a `*_b64` field, never as a
//! string — a non-UTF-8 payload has to survive the round trip.

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};

use super::{AppState, compose, events, forward};
use crate::{
    db::endpoints,
    types::{
        CreateEndpoint, Endpoint, PatchEndpoint, RequestDetail, RequestQuery, RequestSummary,
        TunnelInfo,
    },
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/endpoints", get(list_endpoints).post(create_endpoint))
        .route(
            "/api/endpoints/{id}",
            axum::routing::patch(patch_endpoint).delete(delete_endpoint),
        )
        .route("/api/requests", get(list_requests))
        .route("/api/requests/{id}", get(get_request))
        .route("/api/requests/{id}", delete(delete_request))
        .route("/api/requests/{id}/replay", post(forward::replay))
        .route("/api/compose", post(compose::compose))
        .route("/api/sign", post(compose::sign))
        .route("/api/tunnel", get(get_tunnel))
        .route("/api/events", get(events::stream))
}

// --------------------------------------------------------------- error type

/// Anything a handler can fail with, rendered as `{"error": "..."}`.
pub struct ApiError(pub StatusCode, pub String);

impl ApiError {
    pub fn not_found(what: &str) -> Self {
        Self(StatusCode::NOT_FOUND, format!("no such {what}"))
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, msg.into())
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!(error = %e, "request failed");
        Self(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

// ----------------------------------------------------------------- endpoints

async fn list_endpoints(State(state): State<AppState>) -> ApiResult<Json<Vec<Endpoint>>> {
    Ok(Json(state.db.call(|c| endpoints::list(c)).await?))
}

async fn create_endpoint(
    State(state): State<AppState>,
    Json(input): Json<CreateEndpoint>,
) -> ApiResult<(StatusCode, Json<Endpoint>)> {
    let created = state.db.call(move |c| endpoints::create(c, input)).await?;
    Ok((StatusCode::CREATED, Json(created)))
}

async fn patch_endpoint(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(input): Json<PatchEndpoint>,
) -> ApiResult<Json<Endpoint>> {
    let updated = state
        .db
        .call(move |c| endpoints::patch(c, &id, input))
        .await?
        .ok_or_else(|| ApiError::not_found("endpoint"))?;
    Ok(Json(updated))
}

async fn delete_endpoint(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    // Requests and their forwards cascade; see PRAGMA foreign_keys in db::Db::open.
    let removed = state.db.call(move |c| endpoints::delete(c, &id)).await?;
    if removed {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("endpoint"))
    }
}

// ------------------------------------------------------------------ requests

async fn list_requests(
    State(state): State<AppState>,
    Query(q): Query<RequestQuery>,
) -> ApiResult<Json<Vec<RequestSummary>>> {
    let rows = state
        .db
        .call(move |c| crate::db::requests::list(c, &q))
        .await?;
    Ok(Json(rows))
}

async fn get_request(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<RequestDetail>> {
    let detail = state
        .db
        .call(move |c| crate::db::requests::get_detail(c, &id))
        .await?
        .ok_or_else(|| ApiError::not_found("request"))?;
    Ok(Json(detail))
}

async fn delete_request(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let removed = state
        .db
        .call(move |c| crate::db::requests::delete(c, &id))
        .await?;
    if removed {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("request"))
    }
}

// -------------------------------------------------------------------- tunnel

async fn get_tunnel(State(state): State<AppState>) -> Json<TunnelInfo> {
    let t = state.tunnel.read().await;
    Json(TunnelInfo {
        url: t.url.clone(),
        adapter: t.adapter.to_string(),
        status: t.status,
    })
}
