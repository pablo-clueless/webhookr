-- webhookr schema. Applied once at startup; guarded by PRAGMA user_version.
--
-- `headers` and `resp_headers` are JSON objects. Header names are lowercased on
-- storage and multi-value headers are joined with ", ".
--
-- `verdict` is one of: valid | invalid | unsigned | none.

CREATE TABLE endpoints (
  id              TEXT PRIMARY KEY,
  token           TEXT NOT NULL UNIQUE,
  name            TEXT NOT NULL,
  forward_url     TEXT,
  auto_forward    INTEGER NOT NULL DEFAULT 0,
  scheme          TEXT,
  secret          TEXT,
  resp_status     INTEGER NOT NULL DEFAULT 200,
  resp_body       TEXT NOT NULL DEFAULT '',
  resp_headers    TEXT NOT NULL DEFAULT '{}',
  resp_delay_ms   INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL
);

CREATE TABLE requests (
  id              TEXT PRIMARY KEY,
  endpoint_id     TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  method          TEXT NOT NULL,
  path            TEXT NOT NULL,
  query           TEXT NOT NULL DEFAULT '',
  headers         TEXT NOT NULL,
  body            BLOB NOT NULL,
  remote_addr     TEXT,
  verdict         TEXT NOT NULL,
  verdict_detail  TEXT,
  received_at     INTEGER NOT NULL
);
CREATE INDEX idx_requests_endpoint ON requests(endpoint_id, received_at DESC);

CREATE TABLE forwards (
  id              TEXT PRIMARY KEY,
  request_id      TEXT NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
  target          TEXT NOT NULL,
  status          INTEGER,
  duration_ms     INTEGER,
  resp_body       BLOB,
  error           TEXT,
  sent_at         INTEGER NOT NULL
);
CREATE INDEX idx_forwards_request ON forwards(request_id);
