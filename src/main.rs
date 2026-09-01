//! webhookr — a local-first webhook workbench.
//!
//! Catches inbound webhooks on a public tunnel URL, verifies their signatures,
//! forwards them byte-for-byte to a local dev server, and fires signed test
//! payloads at any target.

// Scaffold: the store, signer, and forwarder APIs are in place ahead of the
// handlers that call them. Remove this once Phase 5 lands and every path is
// reachable — it is here to keep the build quiet, not to hide real dead code.
#![allow(dead_code)]

mod config;
mod db;
mod server;
mod sign;
mod tunnel;
mod types;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::{config::Paths, db::Db, server::AppState, tunnel::TunnelState, types::TunnelStatus};

#[derive(Parser)]
#[command(name = "webhookr", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the workbench: ingress, API, UI, and (unless disabled) a tunnel.
    Serve {
        /// Port to listen on.
        #[arg(long, default_value_t = 4000)]
        port: u16,

        /// Skip the tunnel and serve on localhost only.
        #[arg(long)]
        no_tunnel: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("WEBHOOKR_LOG")
                .unwrap_or_else(|_| "webhookr=info,tower_http=warn".into()),
        )
        .with_target(false)
        .init();

    match Cli::parse().command {
        Command::Serve { port, no_tunnel } => serve(port, !no_tunnel).await,
    }
}

async fn serve(port: u16, tunnel_enabled: bool) -> Result<()> {
    let paths = Paths::resolve()?;
    tracing::info!(root = %paths.root.display(), "config directory");

    let db = Db::open(&paths.db)?;
    db::bootstrap(&db).await?;

    let adapter = tunnel::adapter(tunnel_enabled);
    let state = AppState::new(db, TunnelState::down(adapter.name()))?;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| format!("binding 127.0.0.1:{port} — is another webhookr running?"))?;
    let addr = listener.local_addr()?;

    // Printed rather than logged: this line is a gate condition in HANDOFF.md
    // and must not depend on WEBHOOKR_LOG.
    println!("listening on http://{addr}");

    if tunnel_enabled {
        spawn_tunnel(&state, adapter, addr.port());
    }

    let app = server::router(state);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    Ok(())
}

/// Brings the tunnel up in the background so a slow or missing provider never
/// delays the local listener.
fn spawn_tunnel(state: &AppState, adapter: Box<dyn tunnel::TunnelAdapter>, port: u16) {
    let state = state.clone();

    tokio::spawn(async move {
        {
            let mut t = state.tunnel.write().await;
            t.status = TunnelStatus::Starting;
        }
        state.emit(types::ServerEvent::Tunnel {
            url: None,
            status: TunnelStatus::Starting,
        });

        match adapter.start(port).await {
            Ok(url) => {
                if let Some(url) = &url {
                    println!("tunnel at {url}");
                }
                let mut t = state.tunnel.write().await;
                t.url = url.clone();
                t.status = TunnelStatus::Up;
                drop(t);
                state.emit(types::ServerEvent::Tunnel {
                    url,
                    status: TunnelStatus::Up,
                });
            }
            Err(e) => {
                // A missing provider binary is a normal condition, not a crash:
                // ingress on localhost still works without a public URL.
                tracing::warn!("tunnel unavailable: {e:#}");
                let mut t = state.tunnel.write().await;
                t.status = TunnelStatus::Down;
                drop(t);
                state.emit(types::ServerEvent::Tunnel {
                    url: None,
                    status: TunnelStatus::Down,
                });
            }
        }
    });
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
