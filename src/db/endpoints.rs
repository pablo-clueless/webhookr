//! Queries over the `endpoints` table.

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, Row, params};

use crate::types::{CreateEndpoint, Endpoint, Headers, PatchEndpoint, now_ms};

const COLUMNS: &str = "id, token, name, forward_url, auto_forward, scheme, secret, \
                       resp_status, resp_body, resp_headers, resp_delay_ms, created_at";

fn from_row(row: &Row<'_>) -> rusqlite::Result<Endpoint> {
    let resp_headers: String = row.get("resp_headers")?;
    Ok(Endpoint {
        id: row.get("id")?,
        token: row.get("token")?,
        name: row.get("name")?,
        forward_url: row.get("forward_url")?,
        auto_forward: row.get::<_, i64>("auto_forward")? != 0,
        scheme: row.get("scheme")?,
        secret: row.get("secret")?,
        resp_status: row.get::<_, i64>("resp_status")? as u16,
        resp_body: row.get("resp_body")?,
        // A malformed JSON column is not worth failing a request over; an empty
        // header map is the safe reading.
        resp_headers: serde_json::from_str::<Headers>(&resp_headers).unwrap_or_default(),
        resp_delay_ms: row.get::<_, i64>("resp_delay_ms")?.max(0) as u64,
        created_at: row.get("created_at")?,
    })
}

pub fn list(conn: &Connection) -> Result<Vec<Endpoint>> {
    let sql = format!("SELECT {COLUMNS} FROM endpoints ORDER BY created_at ASC");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map([], from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn get(conn: &Connection, id: &str) -> Result<Option<Endpoint>> {
    let sql = format!("SELECT {COLUMNS} FROM endpoints WHERE id = ?1");
    Ok(conn.query_row(&sql, params![id], from_row).optional()?)
}

/// Resolves the `{token}` in `/in/{token}/...` to its endpoint.
pub fn by_token(conn: &Connection, token: &str) -> Result<Option<Endpoint>> {
    let sql = format!("SELECT {COLUMNS} FROM endpoints WHERE token = ?1");
    Ok(conn.query_row(&sql, params![token], from_row).optional()?)
}

pub fn create(conn: &Connection, input: CreateEndpoint) -> Result<Endpoint> {
    let id = uuid::Uuid::new_v4().to_string();
    // Six hex chars is enough to be unguessable-by-accident while staying
    // typeable into a provider's dashboard.
    let token = uuid::Uuid::new_v4().simple().to_string()[..6].to_string();

    conn.execute(
        "INSERT INTO endpoints
           (id, token, name, forward_url, auto_forward, scheme, secret, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            id,
            token,
            input.name,
            input.forward_url,
            input.auto_forward as i64,
            input.scheme,
            input.secret,
            now_ms(),
        ],
    )?;

    get(conn, &id)?.ok_or_else(|| anyhow::anyhow!("endpoint vanished immediately after insert"))
}

/// Applies only the fields present in `patch`. Returns `None` if no such endpoint.
pub fn patch(conn: &Connection, id: &str, patch: PatchEndpoint) -> Result<Option<Endpoint>> {
    if get(conn, id)?.is_none() {
        return Ok(None);
    }

    // Built one clause at a time so an absent field is untouched and an
    // explicit `null` clears the column.
    let mut sets: Vec<&str> = Vec::new();
    let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    if let Some(v) = patch.name {
        sets.push("name = ?");
        args.push(Box::new(v));
    }
    if let Some(v) = patch.forward_url {
        sets.push("forward_url = ?");
        args.push(Box::new(v));
    }
    if let Some(v) = patch.auto_forward {
        sets.push("auto_forward = ?");
        args.push(Box::new(v as i64));
    }
    if let Some(v) = patch.scheme {
        sets.push("scheme = ?");
        args.push(Box::new(v));
    }
    if let Some(v) = patch.secret {
        sets.push("secret = ?");
        args.push(Box::new(v));
    }
    if let Some(v) = patch.resp_status {
        sets.push("resp_status = ?");
        args.push(Box::new(v as i64));
    }
    if let Some(v) = patch.resp_body {
        sets.push("resp_body = ?");
        args.push(Box::new(v));
    }
    if let Some(v) = patch.resp_headers {
        sets.push("resp_headers = ?");
        args.push(Box::new(serde_json::to_string(&v)?));
    }
    if let Some(v) = patch.resp_delay_ms {
        sets.push("resp_delay_ms = ?");
        args.push(Box::new(v as i64));
    }

    if !sets.is_empty() {
        let sql = format!("UPDATE endpoints SET {} WHERE id = ?", sets.join(", "));
        args.push(Box::new(id.to_string()));
        let refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|a| a.as_ref()).collect();
        conn.execute(&sql, refs.as_slice())?;
    }

    get(conn, id)
}

/// Deletes an endpoint. Its requests (and their forwards) cascade, provided
/// `PRAGMA foreign_keys = ON` — set in [`crate::db::Db::open`].
pub fn delete(conn: &Connection, id: &str) -> Result<bool> {
    let n = conn.execute("DELETE FROM endpoints WHERE id = ?1", params![id])?;
    Ok(n > 0)
}
