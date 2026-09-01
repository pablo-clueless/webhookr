//! Cloudflare quick tunnels via the `cloudflared` binary.
//!
//! Spawns `cloudflared tunnel --url http://localhost:{port}` and scrapes the
//! assigned hostname out of its stderr. The binary is expected on `PATH` and is
//! deliberately not vendored.
//!
//! Note for the open question in HANDOFF.md: quick tunnels hand out a fresh
//! hostname on every start, so provider configs go stale each restart no matter
//! how stable the endpoint token is.

use std::sync::Arc;

use anyhow::{Result, bail};
use async_trait::async_trait;
use tokio::sync::Mutex;

use super::TunnelAdapter;

pub const BINARY: &str = "cloudflared";

/// Shown when the binary is absent. An actionable message, not a panic.
pub const INSTALL_HINT: &str = concat!(
    "`cloudflared` was not found on PATH. Install it with one of:\n",
    "  macOS:   brew install cloudflared\n",
    "  Windows: winget install --id Cloudflare.cloudflared\n",
    "  Linux:   see https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/\n",
    "Or start without a public URL: `webhookr serve --no-tunnel`."
);

#[derive(Default)]
pub struct Cloudflared {
    child: Arc<Mutex<Option<tokio::process::Child>>>,
}

#[async_trait]
impl TunnelAdapter for Cloudflared {
    fn name(&self) -> &'static str {
        "cloudflared"
    }

    async fn start(&self, _port: u16) -> Result<Option<String>> {
        // TODO(phase 4): spawn with piped stderr, read lines until one contains
        // a `*.trycloudflare.com` URL, keep the child in self.child, and log the
        // remaining output. Map a NotFound spawn error to INSTALL_HINT.
        let _ = &self.child;
        bail!("cloudflared adapter not implemented yet (phase 4)")
    }

    async fn stop(&self) -> Result<()> {
        if let Some(mut child) = self.child.lock().await.take() {
            let _ = child.kill().await;
        }
        Ok(())
    }
}

/// Extracts the assigned hostname from a line of `cloudflared` stderr.
///
/// The banner wraps the URL in box-drawing characters, so the URL is located
/// rather than parsed positionally.
pub fn scrape_url(line: &str) -> Option<String> {
    let start = line.find("https://")?;
    let url: String = line[start..]
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != '|' && *c != '"')
        .collect();
    url.contains("trycloudflare.com").then_some(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrapes_the_url_out_of_the_banner() {
        let line =
            "|  https://odd-mouse-vote-plans.trycloudflare.com                              |";
        assert_eq!(
            scrape_url(line).as_deref(),
            Some("https://odd-mouse-vote-plans.trycloudflare.com")
        );
    }

    #[test]
    fn ignores_unrelated_urls() {
        assert!(scrape_url("visit https://cloudflare.com for docs").is_none());
        assert!(scrape_url("no url here").is_none());
    }
}
