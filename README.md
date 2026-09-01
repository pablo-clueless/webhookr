# webhookr

> A developer tool for receiving, inspecting, forwarding, storing, replaying, and generating webhook requests.

Local-first webhook workbench. Catches inbound webhooks on a public tunnel URL, verifies their
signatures, forwards them byte-for-byte to a local dev server, and fires signed test payloads at any
target. Ships as a single binary serving a web UI.

See [HANDOFF.md](HANDOFF.md) for the architecture, the invariants, and the phase gates.

## Status

Phase 0 (scaffold) is complete. Phases 1–5 are stubbed with `TODO(phase N)` markers at each seam;
see the task queue in HANDOFF.md.

## Requirements

- Rust (2024 edition)
- Node 20+ (only to build the UI)
- `cloudflared` on `PATH` for a public URL — optional, `--no-tunnel` works without it

## Running

```sh
# Backend only, no public URL. Serves the API and ingress on :4000.
cargo run -- serve --port 4000 --no-tunnel

# With a public tunnel URL.
cargo run -- serve
```

State lives in `~/.webhookr/webhookr.db`. Set `WEBHOOKR_HOME` to point it elsewhere — useful for
keeping tests off your real database.

### UI

Debug builds proxy unmatched routes to the Vite dev server, so run both:

```sh
npm --prefix ui install
npm --prefix ui run dev     # :5173, proxies /api and /in back to :4000
cargo run -- serve --no-tunnel
```

Release builds serve the UI from assets baked in by `rust-embed`, which is what makes the shipped
artifact a single binary:

```sh
npm --prefix ui run build   # writes dist-ui/
cargo build --release
```

## Layout

```
src/
  main.rs        CLI and wiring
  config.rs      ~/.webhookr paths
  types.rs       shared serde types — mirrored by ui/src/types.ts
  db/            connection actor, migrations, queries
  sign/          Signer trait and the four schemes
  tunnel/        TunnelAdapter trait, cloudflared and none
  server/        ingress, REST, SSE, forwarder, composer
ui/              React + TypeScript (strict) + zustand, built with Vite
dist-ui/         Vite output, embedded at build time
```

## Development

```sh
cargo test                  # phase 2 signature fixtures are #[ignore]d until implemented
cargo fmt && cargo clippy
npm --prefix ui run typecheck
npm --prefix ui run format
```

`ui/src/types.ts` mirrors `src/types.rs` field-for-field and they are kept in sync by hand — change
both in the same commit.

## License

MIT — see [LICENSE](LICENSE).
