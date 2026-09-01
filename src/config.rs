//! Filesystem paths. Everything webhookr owns lives under `~/.webhookr/`.

use std::path::PathBuf;

use anyhow::{Context, Result};

/// Resolved locations for this installation.
#[derive(Debug, Clone)]
pub struct Paths {
    /// `~/.webhookr` (or `$WEBHOOKR_HOME`).
    pub root: PathBuf,
    /// `~/.webhookr/webhookr.db`
    pub db: PathBuf,
}

impl Paths {
    /// Resolves the config root and creates it if missing.
    ///
    /// `WEBHOOKR_HOME` overrides the default location, which keeps integration
    /// tests off the developer's real database.
    pub fn resolve() -> Result<Self> {
        let root = match std::env::var_os("WEBHOOKR_HOME") {
            Some(dir) => PathBuf::from(dir),
            None => dirs::home_dir()
                .context("could not determine the home directory; set WEBHOOKR_HOME")?
                .join(".webhookr"),
        };

        std::fs::create_dir_all(&root)
            .with_context(|| format!("creating config dir {}", root.display()))?;

        let db = root.join("webhookr.db");
        Ok(Self { root, db })
    }
}
