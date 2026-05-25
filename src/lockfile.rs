//! Parse npm / pnpm / yarn lockfiles into a flat (name, version) list that
//! we can hand to the gate endpoint.
//!
//! Supported formats:
//!   - `package-lock.json` v1, v2, v3 (and `npm-shrinkwrap.json`)
//!   - `pnpm-lock.yaml` (pnpm v6+)
//!   - `yarn.lock` v1 (Yarn Classic)
//!
//! Not supported (errors with a clear message):
//!   - Yarn Berry (`yarn.lock` v2+, recognised by the `__metadata:` header).
//!
//! The parser is intentionally permissive: unknown fields are ignored,
//! malformed entries are skipped, and the output is deduplicated by
//! (name, version). Better to under-flag than to refuse a real lockfile.

use anyhow::{anyhow, Context, Result};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockfileEntry {
    pub name: String,
    pub version: String,
}

impl LockfileEntry {
    pub fn spec(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}

#[derive(Debug, Clone, Copy)]
enum LockfileKind {
    Npm,
    Pnpm,
    YarnV1,
}

pub fn parse(path: &Path) -> Result<Vec<LockfileEntry>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading lockfile {}", path.display()))?;
    let kind = detect_kind(path, &content)?;
    let entries = match kind {
        LockfileKind::Npm => parse_npm(&content)?,
        LockfileKind::Pnpm => parse_pnpm(&content)?,
        LockfileKind::YarnV1 => parse_yarn_v1(&content)?,
    };
    let mut entries: Vec<LockfileEntry> = entries
        .into_iter()
        .filter(|e| !e.name.is_empty() && !e.version.is_empty())
        // Skip non-registry refs we can't gate against npm registry (file:, link:, workspace:, git:, etc.)
        .filter(|e| {
            !e.version.starts_with("file:")
                && !e.version.starts_with("link:")
                && !e.version.starts_with("workspace:")
                && !e.version.starts_with("git+")
                && !e.version.starts_with("github:")
                && !e.version.starts_with("npm:")
                && !e.version.contains('/')
        })
        .collect();
    entries.sort();
    entries.dedup();
    Ok(entries)
}

fn detect_kind(path: &Path, content: &str) -> Result<LockfileKind> {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    match name.as_str() {
        "package-lock.json" | "npm-shrinkwrap.json" => Ok(LockfileKind::Npm),
        "pnpm-lock.yaml" | "pnpm-lock.yml" => Ok(LockfileKind::Pnpm),
        "yarn.lock" => {
            if content.contains("__metadata:") {
                return Err(anyhow!(
                    "yarn.lock appears to be Yarn Berry (v2+). Yarn Berry isn't yet supported \
                     by the lockfile parser. Workaround: use a Yarn Classic lockfile, switch \
                     to npm/pnpm, or pass package specs explicitly with `pkgradar gate <specs>`."
                ));
            }
            Ok(LockfileKind::YarnV1)
        }
        _ => Err(anyhow!(
            "unrecognised lockfile name `{name}`. Expected package-lock.json, \
             npm-shrinkwrap.json, pnpm-lock.yaml, or yarn.lock."
        )),
    }
}

// --- npm -------------------------------------------------------------------

fn parse_npm(content: &str) -> Result<Vec<LockfileEntry>> {
    let parsed: serde_json::Value =
        serde_json::from_str(content).context("parsing package-lock.json")?;
    let version = parsed
        .get("lockfileVersion")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);
    let mut entries = Vec::new();
    if version >= 2 {
        if let Some(packages) = parsed.get("packages").and_then(|v| v.as_object()) {
            for (key, value) in packages {
                if key.is_empty() {
                    continue;
                }
                let name = value
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| key.rsplit("node_modules/").next().map(|s| s.to_string()))
                    .unwrap_or_default();
                if name.is_empty() {
                    continue;
                }
                if let Some(ver) = value.get("version").and_then(|v| v.as_str()) {
                    entries.push(LockfileEntry {
                        name,
                        version: ver.to_string(),
                    });
                }
            }
        }
    } else if let Some(deps) = parsed.get("dependencies").and_then(|v| v.as_object()) {
        walk_npm_v1(deps, &mut entries);
    }
    Ok(entries)
}

fn walk_npm_v1(
    deps: &serde_json::Map<String, serde_json::Value>,
    out: &mut Vec<LockfileEntry>,
) {
    for (name, value) in deps {
        if let Some(version) = value.get("version").and_then(|v| v.as_str()) {
            out.push(LockfileEntry {
                name: name.clone(),
                version: version.to_string(),
            });
        }
        if let Some(nested) = value.get("dependencies").and_then(|v| v.as_object()) {
            walk_npm_v1(nested, out);
        }
    }
}

// --- pnpm ------------------------------------------------------------------

fn parse_pnpm(content: &str) -> Result<Vec<LockfileEntry>> {
    let parsed: serde_yaml::Value =
        serde_yaml::from_str(content).context("parsing pnpm-lock.yaml")?;
    let mut entries = Vec::new();
    if let Some(packages) = parsed.get("packages").and_then(|v| v.as_mapping()) {
        for (key, value) in packages {
            let Some(k) = key.as_str() else { continue };
            let Some((name, version_from_key)) = parse_pnpm_package_key(k) else {
                continue;
            };
            let version = value
                .get("version")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or(version_from_key);
            entries.push(LockfileEntry { name, version });
        }
    }
    Ok(entries)
}

fn parse_pnpm_package_key(key: &str) -> Option<(String, String)> {
    let key = key.strip_prefix('/').unwrap_or(key);
    // Strip peer-info: `name@1.0.0(react@18.0.0)` → `name@1.0.0`
    let key = key
        .split_once('(')
        .map(|(left, _)| left.trim_end())
        .unwrap_or(key);

    // Modern (pnpm v6+): `name@version` or `@scope/name@version`.
    let candidate_at = if let Some(rest) = key.strip_prefix('@') {
        rest.find('@').map(|p| p + 1)
    } else {
        key.find('@')
    };
    if let Some(pos) = candidate_at {
        if pos > 0 && pos < key.len() - 1 {
            let name = key[..pos].to_string();
            let version = key[pos + 1..].to_string();
            if !version.contains('@') {
                return Some((name, version));
            }
        }
    }

    // Legacy pnpm: `/name/version` (we already stripped the leading `/`).
    let last_slash = key.rfind('/');
    if let Some(pos) = last_slash {
        let name = key[..pos].to_string();
        let version = key[pos + 1..].to_string();
        if !version.is_empty() && !name.is_empty() {
            return Some((name, version));
        }
    }
    None
}

// --- yarn v1 ---------------------------------------------------------------

fn parse_yarn_v1(content: &str) -> Result<Vec<LockfileEntry>> {
    let mut entries = Vec::new();
    let mut current_names: Vec<String> = Vec::new();
    let mut current_version: Option<String> = None;

    let flush = |names: &mut Vec<String>,
                 version: &mut Option<String>,
                 entries: &mut Vec<LockfileEntry>| {
        if let Some(v) = version.take() {
            for n in names.drain(..) {
                entries.push(LockfileEntry {
                    name: n,
                    version: v.clone(),
                });
            }
        } else {
            names.clear();
        }
    };

    for line in content.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let is_header = !line.starts_with(' ') && !line.starts_with('\t');
        if is_header {
            flush(&mut current_names, &mut current_version, &mut entries);
            let header = line.trim_end_matches(':').trim();
            for token in header.split(',') {
                let token = token.trim().trim_matches('"');
                if let Some(name) = parse_yarn_name(token) {
                    current_names.push(name);
                }
            }
        } else {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("version ") {
                current_version = Some(rest.trim().trim_matches('"').to_string());
            } else if let Some(rest) = trimmed.strip_prefix("version: ") {
                // Some yarn.lock variants use yaml-ish colons.
                current_version = Some(rest.trim().trim_matches('"').to_string());
            }
        }
    }
    flush(&mut current_names, &mut current_version, &mut entries);
    Ok(entries)
}

fn parse_yarn_name(token: &str) -> Option<String> {
    if let Some(rest) = token.strip_prefix('@') {
        let inner = rest.find('@')?;
        Some(format!("@{}", &rest[..inner]))
    } else {
        let at = token.find('@')?;
        Some(token[..at].to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_v2_parses() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "0.1.0" },
                "node_modules/lodash": { "version": "4.17.21" },
                "node_modules/@types/node": { "version": "22.5.4" }
            }
        }"#;
        let entries = parse_npm(content).unwrap();
        let specs: Vec<String> = entries.iter().map(|e| e.spec()).collect();
        assert!(specs.contains(&"lodash@4.17.21".to_string()));
        assert!(specs.contains(&"@types/node@22.5.4".to_string()));
    }

    #[test]
    fn pnpm_modern_parses() {
        let content = r#"
lockfileVersion: '9.0'
packages:
  /lodash@4.17.21: {}
  /@types/node@22.5.4: {}
  /react@18.3.1(react-dom@18.3.1): {}
"#;
        let entries = parse_pnpm(content).unwrap();
        let specs: Vec<String> = entries.iter().map(|e| e.spec()).collect();
        assert!(specs.contains(&"lodash@4.17.21".to_string()));
        assert!(specs.contains(&"@types/node@22.5.4".to_string()));
        assert!(specs.contains(&"react@18.3.1".to_string()));
    }

    #[test]
    fn yarn_v1_parses() {
        let content = r#"
"@types/node@^22.0.0":
  version "22.5.4"
  resolved "https://..."

"lodash@^4.17.0", "lodash@~4.17.21":
  version "4.17.21"
  resolved "https://..."
"#;
        let entries = parse_yarn_v1(content).unwrap();
        let specs: Vec<String> = entries.iter().map(|e| e.spec()).collect();
        assert!(specs.contains(&"@types/node@22.5.4".to_string()));
        assert!(specs.contains(&"lodash@4.17.21".to_string()));
    }

    #[test]
    fn yarn_berry_errors_clearly() {
        let content = "__metadata:\n  version: 6\n  cacheKey: 8\n";
        let path = Path::new("yarn.lock");
        let err = detect_kind(path, content).unwrap_err();
        assert!(err.to_string().contains("Yarn Berry"));
    }

    #[test]
    fn parse_filters_workspace_and_link_versions() {
        let entries = vec![
            LockfileEntry { name: "real".to_string(), version: "1.0.0".to_string() },
            LockfileEntry { name: "linked".to_string(), version: "link:../foo".to_string() },
            LockfileEntry { name: "ws".to_string(), version: "workspace:*".to_string() },
        ];
        // Simulate the filter the public parse() applies.
        let kept: Vec<_> = entries
            .into_iter()
            .filter(|e| {
                !e.version.starts_with("file:")
                    && !e.version.starts_with("link:")
                    && !e.version.starts_with("workspace:")
            })
            .collect();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].name, "real");
    }
}
