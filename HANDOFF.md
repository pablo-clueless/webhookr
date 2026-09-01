# webhookr — HANDOFF

Local-first webhook workbench. Catches inbound webhooks on a public tunnel URL, verifies their signatures, forwards them byte-for-byte to a local dev server, and fires signed test payloads at any target. Ships as a single binary serving a web UI.

Read this whole document before writing code. Every phase has a mechanical gate with an exact expected output. Do not advance past a failing gate.

---

## Locked decisions

| Decision           | Choice                                                     | Notes                                                |
| ------------------ | ---------------------------------------------------------- | ---------------------------------------------------- |
| Backend            | Rust — axum + tokio                                        | LOCKED                                               |
| Storage            | SQLite via `rusqlite` (`bundled` feature)                  | LOCKED. No external sqlite dependency.               |
| Tunnel             | Pluggable `TunnelAdapter` trait, cloudflared default       | LOCKED. Binary expected on `PATH`; do not vendor it. |
| Signatures         | Generate **and** verify                                    | LOCKED. Both directions, same scheme registry.       |
| Frontend           | React + TypeScript (strict) + zustand, built with Vite     | LOCKED                                               |
| Frontend transport | SSE server→client, REST client→server                      | LOCKED. No WebSocket.                                |
| UI delivery        | `rust-embed` in release, proxy to Vite dev server in debug | LOCKED                                               |
| Distribution       | **Undecided** — see Open questions                         | Build to a plain `cargo run` for now.                |

## Non-goals for v1

- Multi-user, auth, accounts, hosted mode
- Request mutation or scripting hooks
- Non-HTTP transports
- Persisting tunnel URLs across restarts
- Provider event-catalog fixtures (Stripe's full event zoo) — the composer takes freeform JSON

---

## Repo layout

```
webhookr/
  Cargo.toml
  src/
    main.rs               clap CLI, wiring
    config.rs             paths, ~/.webhookr/
    db/
      mod.rs              connection actor, migrations
      schema.sql
      endpoints.rs
      requests.rs
      forwards.rs
    sign/
      mod.rs              Signer trait + registry
      stripe.rs
      github.rs
      svix.rs
      hmac_generic.rs
    tunnel/
      mod.rs              TunnelAdapter trait
      cloudflared.rs
      none.rs
    server/
      mod.rs              router assembly
      ingress.rs          /in/{*path} catch-all
      api.rs              REST
      events.rs           SSE broadcast
      forward.rs          replay to target
      compose.rs          fire arbitrary payload
    types.rs              shared serde types
  ui/
    package.json
    vite.config.ts
    src/
      main.tsx
      App.tsx
      store.ts            zustand
      api.ts              REST client
      events.ts           EventSource wiring
      types.ts            mirrors src/types.rs
      components/
        TunnelBar.tsx
        EndpointList.tsx
        RequestList.tsx
        RequestDetail.tsx
        ComposePanel.tsx
  dist-ui/                vite output, embedded at build time
```

A UI shell already exists as a single-file prototype (`hookr-ui.jsx`) with the layout, palette, and mock data. Port it into `ui/src` and split it along the component boundaries above. Convert to `.tsx`, strict mode. It is a visual reference, not production code — its state is `useState`; the real one is zustand.

---

## Invariants

These are the things that will silently break and cost hours. Preserve them.

**1. Raw body bytes are never round-tripped.**
The body is captured as `axum::body::Bytes`, stored as a SQLite `BLOB`, and forwarded as those same bytes. Nothing in the path may deserialize and re-serialize it. A `serde_json` round-trip reorders keys and normalizes whitespace, which changes the HMAC digest — and only for _some_ payloads, so it presents as flakiness rather than a bug. Parse only for display, in the browser, from a base64 field.

**2. Never use `Json<T>` as an ingress extractor.**
It consumes the body and rejects non-JSON. Ingress accepts any content type including empty bodies and `application/x-www-form-urlencoded`.

**3. Disable automatic decompression on the forwarding client.**
Build `reqwest::Client` with `.no_gzip().no_brotli().no_deflate()`. Otherwise a gzipped inbound body is silently decompressed and the forwarded bytes differ from the captured bytes.

**4. Rewrite exactly three headers on forward, pass everything else through.**
`Host` → target host. `Content-Length` → recomputed. `Accept-Encoding` → dropped. Every other header, including the signature header, is forwarded verbatim — the whole point is that the local handler sees what the provider sent.

**5. Compare digests in constant time.**
Use `subtle::ConstantTimeEq`. Never `==` on digest bytes.

**6. `rusqlite::Connection` is not `Sync`.**
Do not wrap it in `Arc` and share it across handlers. Run a single writer task owning the connection, fed by a `tokio::sync::mpsc` channel with oneshot reply channels. Alternative accepted: `spawn_blocking` over a `Mutex<Connection>`. Pick one in Phase 1 and do not mix.

**7. Replay re-signs by default.**
Stripe rejects signatures older than its tolerance window, so replaying a captured request with its original `t=` value will fail at the receiver. Replay recomputes the signature with a fresh timestamp when the endpoint has a secret. A `preserve_signature: true` flag on the replay request keeps the original bytes — needed for testing that your handler _rejects_ stale deliveries.

---

## Data model

`~/.webhookr/webhookr.db`

```sql
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
```

`verdict` ∈ `valid | invalid | unsigned | none`.

- `valid` — digest matched
- `invalid` — a signature header was present and did not match
- `unsigned` — endpoint has a scheme configured, request carried no signature header
- `none` — endpoint has no scheme configured

`headers` and `resp_headers` are JSON objects. Header names lowercased on storage; multi-value headers joined with `, `.

---

## Signature schemes

Get these exactly right — they are the reason the tool exists. All use HMAC-SHA256.

**stripe**
Header `stripe-signature`, value `t=<unix_secs>,v1=<hex>`. Signed payload is `{t}.{raw_body}` joined with a literal period. Verification tolerance defaults to 300s; a request outside tolerance is `invalid` with detail naming the skew. A header may carry multiple `v1=` entries — match if any one matches.

**github**
Header `x-hub-signature-256`, value `sha256=<hex>`. Signed payload is the raw body alone.

**svix**
Headers `svix-id`, `svix-timestamp`, `svix-signature`. Signature value is space-separated versioned entries, each `v1,<base64>`. Signed payload is `{svix-id}.{svix-timestamp}.{raw_body}`. The secret has its `whsec_` prefix stripped and the remainder base64-decoded before use as HMAC key. Tolerance 300s.

**hmac_generic**
Config-driven: header name, digest encoding (`hex` | `base64`), optional value prefix. Signed payload is the raw body alone.

### Signature test fixtures

Use these in unit tests. They are real digests, verified.

```
body    = {"id":"evt_test","type":"ping"}
```

stripe — secret `whsec_test_secret`, t = `1700000000`, signed payload `1700000000.{"id":"evt_test","type":"ping"}`:

```
76e93d7667b36f8aab799377027b5ad5c17365edfaca34f11cc7c9f570f94a2a
```

github — secret `ghs_test_secret`, signed payload is the body alone:

```
575f31703fceff0bc48b31ddafa528e733869cee105804f38f19b7183c0c6bff
```

---

## API contract

Frontend types in `ui/src/types.ts` mirror `src/types.rs` field-for-field. Keep them in sync manually; a drift here is the most likely source of silent UI bugs.

```
GET    /api/endpoints                 -> Endpoint[]
POST   /api/endpoints                 { name, scheme?, secret?, forward_url?, auto_forward } -> Endpoint
PATCH  /api/endpoints/:id             partial Endpoint -> Endpoint
DELETE /api/endpoints/:id             -> 204

GET    /api/requests?endpoint_id=&limit=&before=   -> RequestSummary[]
GET    /api/requests/:id              -> RequestDetail
DELETE /api/requests/:id              -> 204
POST   /api/requests/:id/replay       { target?, preserve_signature? } -> Forward

POST   /api/compose                   { target, method, headers, body, scheme?, secret? } -> Forward
POST   /api/sign                      { body, scheme, secret, timestamp? } -> { headers: Record<string,string> }

GET    /api/tunnel                    -> { url: string | null, adapter: string, status: "up"|"down"|"starting" }

GET    /api/events                    SSE
```

Bodies cross the API base64-encoded in a `body_b64` field. Never as a string — a non-UTF-8 body must survive the trip.

SSE frames, one JSON object per `data:` line, `event:` names as given:

```
event: request      { request: RequestSummary }
event: forward      { request_id: string, forward: Forward }
event: tunnel       { url: string | null, status: string }
```

The UI's zustand store subscribes once at mount and prepends `request` frames to the active list. The list must accept pushes from outside React's tree — this is why it's zustand and not `useState`.

---

## Build order

Adapter and UI work is deliberately last. The byte-fidelity path is the thing everything else depends on, so it is proven first, in isolation, before any surface area exists to hide it.

### Phase 0 — Scaffold

Cargo project, clap CLI with `webhookr serve [--port 4000] [--no-tunnel]`, config dir creation, migrations run at startup.

**Gate:**

```
cargo run -- serve --port 4000 --no-tunnel
```

Expected: process stays up, prints `listening on http://127.0.0.1:4000`, and `~/.webhookr/webhookr.db` exists.

### Phase 1 — Ingress + store

Catch-all route `/in/{*path}`, `Bytes` extractor, header capture, insert into `requests`. Seed one endpoint with token `8f2ac1` at first run. Configurable response echoed back.

**Gate:**

```
curl -sS -X POST localhost:4000/in/8f2ac1 -H 'content-type: application/json' -d '{"a":1}'
sqlite3 ~/.webhookr/webhookr.db 'SELECT hex(body) FROM requests ORDER BY received_at DESC LIMIT 1'
```

Expected exactly:

```
7B2261223A317D
```

Any other value means invariant 1 is already broken. Stop and fix before continuing.

**Second gate — non-JSON and empty bodies must not 4xx:**

```
curl -sS -o /dev/null -w '%{http_code}' -X GET localhost:4000/in/8f2ac1
curl -sS -o /dev/null -w '%{http_code}' -X POST localhost:4000/in/8f2ac1 --data-binary @/bin/ls
```

Expected: `200` twice.

### Phase 2 — Signers

`Signer` trait with `sign` and `verify`. All four schemes. Verdict computed at ingress and stored.

**Gate:** `cargo test sign` — the two fixture digests above must reproduce exactly, and each scheme must round-trip sign→verify.

**Second gate:**

```
sqlite3 ~/.webhookr/webhookr.db "UPDATE endpoints SET scheme='github', secret='ghs_test_secret' WHERE token='8f2ac1'"
curl -sS -X POST localhost:4000/in/8f2ac1 \
  -H 'content-type: application/json' \
  -H 'x-hub-signature-256: sha256=575f31703fceff0bc48b31ddafa528e733869cee105804f38f19b7183c0c6bff' \
  -d '{"id":"evt_test","type":"ping"}'
sqlite3 ~/.webhookr/webhookr.db 'SELECT verdict FROM requests ORDER BY received_at DESC LIMIT 1'
```

Expected: `valid`. Flip one hex character in the header and re-run: expected `invalid`.

### Phase 3 — Forwarder

Forward captured requests to `forward_url`, auto on capture when `auto_forward`, manually via replay. Record into `forwards`.

**Gate:** run an echo server that returns the SHA-256 of the body it received:

```
python3 -c "
import hashlib,http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(s):
        b=s.rfile.read(int(s.headers['content-length']))
        d=hashlib.sha256(b).hexdigest().encode()
        s.send_response(200); s.send_header('content-length',str(len(d))); s.end_headers(); s.wfile.write(d)
    def log_message(s,*a): pass
http.server.HTTPServer(('',3000),H).serve_forever()" &
```

Send a payload through ingress with forwarding on, then compare:

```
sqlite3 ~/.webhookr/webhookr.db 'SELECT resp_body FROM forwards ORDER BY sent_at DESC LIMIT 1'
```

against the local SHA-256 of the same bytes. They must match. Repeat with a gzipped body to prove invariant 3.

### Phase 4 — Tunnel

`TunnelAdapter` trait: `start(port) -> Result<String>`, `stop()`. `cloudflared` implementation spawns `cloudflared tunnel --url http://localhost:{port}` and scrapes the assigned URL from stderr. `none` adapter returns `None`. Missing binary produces an actionable error naming the install command, not a panic.

**Gate:** `cargo run -- serve` prints a `trycloudflare.com` URL; a POST to `{url}/in/8f2ac1` from outside the machine lands in the store.

### Phase 5 — UI

Port the prototype, wire REST + SSE, zustand store, compose panel calling `/api/compose`.

**Gate:** with the server running, a `curl` to the ingress URL causes a new row to appear in the browser list without a refresh, within 1s.

---

## Task queue

1. Phase 0 scaffold — acceptance: both Phase 0 gate conditions.
2. DB actor with the chosen concurrency model — acceptance: 100 concurrent ingress POSTs via `xargs -P 20` produce exactly 100 rows, no `SQLITE_BUSY` in logs.
3. Phase 1 ingress — acceptance: both Phase 1 gates.
4. Signer registry + four schemes — acceptance: Phase 2 gates, plus a stale-timestamp Stripe request yielding `invalid` with skew in `verdict_detail`.
5. Endpoint CRUD API — acceptance: create, patch, delete round-trips via curl; deleting an endpoint cascades its requests.
6. Forwarder — acceptance: Phase 3 gate including the gzip case.
7. Replay with re-signing — acceptance: replaying a Stripe request against a verifying receiver succeeds; with `preserve_signature: true` against the same receiver it fails on tolerance.
8. SSE broadcast — acceptance: two browser tabs both receive the same `request` frame.
9. Tunnel adapter — acceptance: Phase 4 gate, plus a clean error when `cloudflared` is absent from `PATH`.
10. UI port + wiring — acceptance: Phase 5 gate.

---

## Open questions

- **Distribution.** `cargo install` / brew / curl script, or an npm wrapper shipping prebuilt per-platform binaries. Unresolved; affects CI only, not the code. Decide before Phase 4.
- **Retention.** Requests accumulate without bound. Cap by count per endpoint, by age, or by total DB size? Bodies are the bulk. Not needed for v1 but the schema should not have to change.
- **Endpoint token stability.** Cloudflare quick tunnels hand out a new hostname on every start, so provider configs go stale each restart regardless of token stability. Worth supporting named Cloudflare tunnels for people with an account, or leaving to the user?
- **Response templating.** Should `resp_body` support substitution from the inbound payload, or stay static? Static for v1.
