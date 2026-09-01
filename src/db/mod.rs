//! SQLite access.
//!
//! # Concurrency model (invariant 6)
//!
//! `rusqlite::Connection` is `Send` but not `Sync`, so it cannot be wrapped in
//! an `Arc` and shared across axum handlers. This crate resolves that with a
//! **single writer task owning the connection**, fed by a `tokio::sync::mpsc`
//! channel whose messages carry `oneshot` reply channels.
//!
//! That choice is locked. Do not introduce a `Mutex<Connection>` +
//! `spawn_blocking` path alongside it — mixing the two reintroduces the
//! contention this design exists to avoid.
//!
//! Every query goes through [`Db::call`], which hands a `&mut Connection` to a
//! closure running on the actor thread.

pub mod endpoints;
pub mod forwards;
pub mod requests;

use std::path::Path;

use anyhow::{Context, Result, anyhow};
use rusqlite::Connection;
use tokio::sync::{mpsc, oneshot};

/// A unit of work for the actor thread.
type Job = Box<dyn FnOnce(&mut Connection) + Send + 'static>;

/// Bump this and add a branch in [`migrate`] when the schema changes.
const SCHEMA_VERSION: i32 = 1;

const SCHEMA: &str = include_str!("schema.sql");

/// Handle to the database actor. Cheap to clone; every clone talks to the same
/// single connection.
#[derive(Clone)]
pub struct Db {
    tx: mpsc::Sender<Job>,
}

impl Db {
    /// Opens (creating if needed) the database at `path`, applies migrations,
    /// then moves the connection onto a dedicated thread.
    ///
    /// Migrations run on the calling thread so a broken schema fails startup
    /// loudly rather than poisoning the actor after the server is already up.
    pub fn open(path: &Path) -> Result<Self> {
        let mut conn = Connection::open(path)
            .with_context(|| format!("opening database {}", path.display()))?;

        // WAL keeps readers off the writer's back; foreign_keys is required for
        // the ON DELETE CASCADE on requests and forwards to actually fire.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;

        migrate(&mut conn)?;

        // Bounded: backpressure on a flood of ingress beats unbounded memory.
        let (tx, mut rx) = mpsc::channel::<Job>(256);

        std::thread::Builder::new()
            .name("webhookr-db".into())
            .spawn(move || {
                while let Some(job) = rx.blocking_recv() {
                    job(&mut conn);
                }
                tracing::debug!("database actor stopped");
            })
            .context("spawning the database actor thread")?;

        Ok(Self { tx })
    }

    /// Runs `f` on the actor thread and awaits its result.
    pub async fn call<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let (reply_tx, reply_rx) = oneshot::channel();

        self.tx
            .send(Box::new(move |conn| {
                // The receiver is gone if the caller was cancelled; that is not
                // an error, the work simply has nobody to return to.
                let _ = reply_tx.send(f(conn));
            }))
            .await
            .map_err(|_| anyhow!("database actor is no longer running"))?;

        reply_rx
            .await
            .map_err(|_| anyhow!("database actor dropped the reply channel"))?
    }
}

/// Applies the schema to a fresh database, tracked via `PRAGMA user_version`.
fn migrate(conn: &mut Connection) -> Result<()> {
    let version: i32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;

    if version >= SCHEMA_VERSION {
        return Ok(());
    }

    let tx = conn.transaction()?;
    if version < 1 {
        tx.execute_batch(SCHEMA).context("applying schema.sql")?;
    }
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    tx.commit()?;

    tracing::info!(from = version, to = SCHEMA_VERSION, "migrated database");
    Ok(())
}

/// Token handed to the endpoint created on first run, so the gates in
/// HANDOFF.md work against a clean checkout without a setup step.
pub const SEED_TOKEN: &str = "8f2ac1";

/// Creates the default endpoint if the store has none. Idempotent.
pub async fn bootstrap(db: &Db) -> Result<()> {
    db.call(|conn| {
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM endpoints", [], |r| r.get(0))?;
        if count > 0 {
            return Ok(());
        }

        conn.execute(
            "INSERT INTO endpoints (id, token, name, auto_forward, resp_status, created_at)
             VALUES (?1, ?2, ?3, 0, 200, ?4)",
            rusqlite::params![
                uuid::Uuid::new_v4().to_string(),
                SEED_TOKEN,
                "Default",
                crate::types::now_ms(),
            ],
        )?;

        tracing::info!(token = SEED_TOKEN, "seeded default endpoint");
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn migrates_and_seeds_a_fresh_database() {
        let dir = std::env::temp_dir().join(format!("webhookr-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Db::open(&dir.join("test.db")).unwrap();

        bootstrap(&db).await.unwrap();
        bootstrap(&db).await.unwrap(); // idempotent

        let tokens: Vec<String> = db
            .call(|conn| {
                let mut stmt = conn.prepare("SELECT token FROM endpoints")?;
                let rows = stmt
                    .query_map([], |r| r.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await
            .unwrap();

        assert_eq!(tokens, vec![SEED_TOKEN.to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
