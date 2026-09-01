//! Public-URL adapters.
//!
//! The tunnel is pluggable so the rest of the app never learns which provider
//! is in use. `cloudflared` is the default; `none` is what `--no-tunnel`
//! selects and what the Phase 0/1 gates run against.

pub mod cloudflared;
pub mod none;

use anyhow::Result;
use async_trait::async_trait;

use crate::types::TunnelStatus;

#[async_trait]
pub trait TunnelAdapter: Send + Sync {
    /// Name reported on `GET /api/tunnel`.
    fn name(&self) -> &'static str;

    /// Opens a tunnel to `127.0.0.1:{port}` and resolves to its public URL.
    ///
    /// A missing provider binary must produce an actionable error naming the
    /// install command — never a panic.
    async fn start(&self, port: u16) -> Result<Option<String>>;

    /// Tears the tunnel down. Idempotent.
    async fn stop(&self) -> Result<()>;
}

/// Current tunnel state, shared with the API and the SSE broadcaster.
#[derive(Debug, Clone)]
pub struct TunnelState {
    pub url: Option<String>,
    pub adapter: &'static str,
    pub status: TunnelStatus,
}

impl TunnelState {
    pub fn down(adapter: &'static str) -> Self {
        Self {
            url: None,
            adapter,
            status: TunnelStatus::Down,
        }
    }
}

/// Chooses an adapter. `--no-tunnel` selects [`none::NoTunnel`].
pub fn adapter(enabled: bool) -> Box<dyn TunnelAdapter> {
    if enabled {
        Box::new(cloudflared::Cloudflared::default())
    } else {
        Box::new(none::NoTunnel)
    }
}
