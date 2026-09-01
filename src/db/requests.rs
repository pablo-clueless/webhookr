//! Queries over the `requests` table.
//!
//! The `body` column is a BLOB holding the exact bytes that arrived. Nothing in
//! this module parses it (invariant 1) — it goes in as `Bytes` and comes out as
//! `Vec<u8>`, and only the browser ever interprets it.

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, Row, params};

use crate::types::{Headers, RequestDetail, RequestQuery, RequestSummary, Verdict, now_ms};

/// A captured request on its way into the store.
pub struct NewRequest {
    pub endpoint_id: String,
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Headers,
    /// The raw bytes, exactly as received.
    pub body: Vec<u8>,
    pub remote_addr: Option<String>,
    pub verdict: Verdict,
    pub verdict_detail: Option<String>,
}

const SUMMARY_COLUMNS: &str = "id, endpoint_id, method, path, query, remote_addr, \
                               verdict, verdict_detail, LENGTH(body) AS size, received_at";

fn summary_from_row(row: &Row<'_>) -> rusqlite::Result<RequestSummary> {
    let verdict: String = row.get("verdict")?;
    Ok(RequestSummary {
        id: row.get("id")?,
        endpoint_id: row.get("endpoint_id")?,
        method: row.get("method")?,
        path: row.get("path")?,
        query: row.get("query")?,
        remote_addr: row.get("remote_addr")?,
        verdict: verdict.parse().unwrap_or(Verdict::None),
        verdict_detail: row.get("verdict_detail")?,
        size: row.get::<_, i64>("size")?.max(0) as u64,
        received_at: row.get("received_at")?,
    })
}

/// Inserts a captured request and returns its list-row form, ready to broadcast
/// over SSE.
pub fn insert(conn: &Connection, req: NewRequest) -> Result<RequestSummary> {
    let id = uuid::Uuid::new_v4().to_string();
    let received_at = now_ms();
    let size = req.body.len() as u64;

    conn.execute(
        "INSERT INTO requests
           (id, endpoint_id, method, path, query, headers, body, remote_addr,
            verdict, verdict_detail, received_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            id,
            req.endpoint_id,
            req.method,
            req.path,
            req.query,
            serde_json::to_string(&req.headers)?,
            req.body,
            req.remote_addr,
            req.verdict.as_str(),
            req.verdict_detail,
            received_at,
        ],
    )?;

    Ok(RequestSummary {
        id,
        endpoint_id: req.endpoint_id,
        method: req.method,
        path: req.path,
        query: req.query,
        remote_addr: req.remote_addr,
        verdict: req.verdict,
        verdict_detail: req.verdict_detail,
        size,
        received_at,
    })
}

/// Newest first. `before` is a `received_at` cursor for pagination.
pub fn list(conn: &Connection, q: &RequestQuery) -> Result<Vec<RequestSummary>> {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000) as i64;
    let sql = format!(
        "SELECT {SUMMARY_COLUMNS} FROM requests
         WHERE (?1 IS NULL OR endpoint_id = ?1)
           AND (?2 IS NULL OR received_at < ?2)
         ORDER BY received_at DESC
         LIMIT ?3"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(params![q.endpoint_id, q.before, limit], summary_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn get_summary(conn: &Connection, id: &str) -> Result<Option<RequestSummary>> {
    let sql = format!("SELECT {SUMMARY_COLUMNS} FROM requests WHERE id = ?1");
    Ok(conn
        .query_row(&sql, params![id], summary_from_row)
        .optional()?)
}

/// The raw captured bytes. Used by the forwarder, which must send these
/// untouched.
pub fn get_body(conn: &Connection, id: &str) -> Result<Option<Vec<u8>>> {
    Ok(conn
        .query_row(
            "SELECT body FROM requests WHERE id = ?1",
            params![id],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?)
}

pub fn get_headers(conn: &Connection, id: &str) -> Result<Option<Headers>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT headers FROM requests WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(raw.map(|s| serde_json::from_str(&s).unwrap_or_default()))
}

pub fn get_detail(conn: &Connection, id: &str) -> Result<Option<RequestDetail>> {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let Some(summary) = get_summary(conn, id)? else {
        return Ok(None);
    };

    Ok(Some(RequestDetail {
        headers: get_headers(conn, id)?.unwrap_or_default(),
        body_b64: STANDARD.encode(get_body(conn, id)?.unwrap_or_default()),
        forwards: super::forwards::list_for_request(conn, id)?,
        summary,
    }))
}

pub fn delete(conn: &Connection, id: &str) -> Result<bool> {
    let n = conn.execute("DELETE FROM requests WHERE id = ?1", params![id])?;
    Ok(n > 0)
}
