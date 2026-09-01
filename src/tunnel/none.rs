//! The null adapter: no public URL, nothing to tear down.
//!
//! Selected by `--no-tunnel`. Ingress still works on `127.0.0.1`.

use anyhow::Result;
use async_trait::async_trait;

use super::TunnelAdapter;

pub struct NoTunnel;

#[async_trait]
impl TunnelAdapter for NoTunnel {
    fn name(&self) -> &'static str {
        "none"
    }

    async fn start(&self, _port: u16) -> Result<Option<String>> {
        Ok(None)
    }

    async fn stop(&self) -> Result<()> {
        Ok(())
    }
}
