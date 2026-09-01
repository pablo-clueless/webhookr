//! Queries over the `forwards` table — one row per delivery attempt to a target.

use anyhow::Result;
use rusqlite::{Connection, Row, params};

use crate::types::{Forward, now_ms};

/// The outcome of one delivery attempt, on its way into the store.
pub struct NewForward {
    pub request_id: String,
    pub target: String,
    pub status: Option<u16>,
    pub duration_ms: Option<i64>,
    pub resp_body: Option<Vec<u8>>,
    /// Transport-level failure (DNS, refused, timeout). `None` when the target
    /// answered at all, even with a 5xx.
    pub error: Option<String>,
}

fn from_row(row: &Row<'_>) -> rusqlite::Result<Forward> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let resp_body: Option<Vec<u8>> = row.get("resp_body")?;
    Ok(Forward {
        id: row.get("id")?,
        request_id: row.get("request_id")?,
        target: row.get("target")?,
        status: row.get::<_, Option<i64>>("status")?.map(|s| s as u16),
        duration_ms: row.get("duration_ms")?,
        resp_body_b64: resp_body.map(|b| STANDARD.encode(b)),
        error: row.get("error")?,
        sent_at: row.get("sent_at")?,
    })
}

pub fn insert(conn: &Connection, f: NewForward) -> Result<Forward> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let id = uuid::Uuid::new_v4().to_string();
    let sent_at = now_ms();

    conn.execute(
        "INSERT INTO forwards
           (id, request_id, target, status, duration_ms, resp_body, error, sent_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            id,
            f.request_id,
            f.target,
            f.status.map(|s| s as i64),
            f.duration_ms,
            f.resp_body,
            f.error,
            sent_at,
        ],
    )?;

    Ok(Forward {
        id,
        request_id: f.request_id,
        target: f.target,
        status: f.status,
        duration_ms: f.duration_ms,
        resp_body_b64: f.resp_body.map(|b| STANDARD.encode(b)),
        error: f.error,
        sent_at,
    })
}

pub fn list_for_request(conn: &Connection, request_id: &str) -> Result<Vec<Forward>> {
    let mut stmt = conn.prepare(
        "SELECT id, request_id, target, status, duration_ms, resp_body, error, sent_at
         FROM forwards WHERE request_id = ?1 ORDER BY sent_at ASC",
    )?;
    let rows = stmt
        .query_map(params![request_id], from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}
