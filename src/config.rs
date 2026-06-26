//! Repo-local `.pkgradar.yml` configuration.
//!
//! Read once at the start of `gate` / `scan`, merged with CLI flags (CLI
//! flags win on conflict). Missing file is treated as empty config — no error.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// One waiver: downgrade a matched blocked finding (still scanned + reported,
/// not failing). `package` is a name glob (`*` wildcard); `versions` is an
/// optional semver requirement (omit = all versions). Optional `expires`
/// (YYYY-MM-DD) makes the waiver lapse so it can't become permanent.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct Waiver {
    pub package: String,
    pub versions: Option<String>,
    pub reason: String,
    pub reviewer: Option<String>,
    pub expires: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct RepoConfig {
    /// Block when a spec's risk is at or above this level. Mirrors the CLI's
    /// `--fail-on` flag; CLI argument wins when both are present.
    pub fail_on: Option<String>,

    /// Opt in to also failing on known-vulnerability advisories (plain CVEs)
    /// at or above this severity (low|moderate|high|critical). Mirrors the
    /// CLI's `--fail-on-cve`; CLI argument wins. Off (advisory-only) when
    /// absent.
    #[serde(default)]
    pub fail_on_cve: Option<String>,

    /// HTTP timeout per request, in milliseconds. CLI `--timeout-ms` wins.
    pub timeout_ms: Option<u64>,

    /// When the API call fails for network/transport reasons, exit 0 with a
    /// warning instead of erroring out. CI pipelines should not be blocked
    /// by a momentary PkgRadar outage. Default: true.
    pub fail_open: Option<bool>,

    /// Specs (`name@version`) that bypass the gate entirely. Useful for
    /// known false positives the operator has reviewed and accepted.
    /// Wildcards aren't supported in v1 — list explicit versions.
    pub allowlist: Vec<String>,

    /// Specs to always include in the gate call alongside the lockfile /
    /// CLI args. Rarely useful — mostly for verifying a specific release
    /// hasn't been hijacked.
    pub watchlist: Vec<String>,

    /// Downgrade reviewed false positives (see `Waiver`). Unlike `allowlist`
    /// (bypass before scan), waived packages are still scanned + reported.
    #[serde(default)]
    pub waivers: Vec<Waiver>,
}

/// Resolve the config file path. If `--config <path>` was given, use that.
/// Otherwise check `.pkgradar.yml` and `.pkgradar.yaml` in the current dir.
/// Returns `None` if no config file was found — callers fall back to all-
/// CLI-arg defaults.
pub fn resolve_path(explicit: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        let path = PathBuf::from(p);
        return path.exists().then_some(path);
    }
    for candidate in [".pkgradar.yml", ".pkgradar.yaml"] {
        let path = Path::new(candidate);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }
    None
}

pub fn load(path: Option<&Path>) -> Result<RepoConfig> {
    let Some(path) = path else {
        return Ok(RepoConfig::default());
    };
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let cfg: RepoConfig =
        serde_yaml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_is_default() {
        let cfg: RepoConfig = serde_yaml::from_str("").unwrap_or_default();
        assert!(cfg.fail_on.is_none());
        assert!(cfg.allowlist.is_empty());
    }

    #[test]
    fn waivers_parse_from_yaml() {
        let src = r#"
waivers:
  - package: "sharp"
    versions: ">=0.33.0, <0.34.0"
    reason: "reviewed FP"
    reviewer: "ops@x"
    expires: "2026-09-01"
  - package: "left-pad"
    reason: "trivial"
"#;
        let cfg: RepoConfig = serde_yaml::from_str(src).unwrap();
        assert_eq!(cfg.waivers.len(), 2);
        assert_eq!(cfg.waivers[0].package, "sharp");
        assert_eq!(
            cfg.waivers[0].versions.as_deref(),
            Some(">=0.33.0, <0.34.0")
        );
        assert_eq!(cfg.waivers[0].expires.as_deref(), Some("2026-09-01"));
        assert!(cfg.waivers[1].versions.is_none());
        assert!(cfg.waivers[1].reviewer.is_none());
    }

    #[test]
    fn full_config_round_trip() {
        let src = r#"
fail_on: review
timeout_ms: 30000
fail_open: false
allowlist:
  - "@types/node@22.5.4"
  - "lodash@4.17.21"
watchlist:
  - "react@18.3.1"
"#;
        let cfg: RepoConfig = serde_yaml::from_str(src).unwrap();
        assert_eq!(cfg.fail_on.as_deref(), Some("review"));
        assert_eq!(cfg.timeout_ms, Some(30_000));
        assert_eq!(cfg.fail_open, Some(false));
        assert_eq!(cfg.allowlist.len(), 2);
        assert_eq!(cfg.watchlist, vec!["react@18.3.1"]);
    }
}
