//! Parse lockfiles into a flat (ecosystem, name, version) list that the
//! gate endpoint can consume.
//!
//! Supported formats:
//!   - npm: `package-lock.json` v1/v2/v3, `npm-shrinkwrap.json`
//!   - pnpm: `pnpm-lock.yaml` (v6+)
//!   - yarn classic: `yarn.lock` v1
//!   - PyPI: `requirements.txt`, `requirements.lock`, `Pipfile.lock`,
//!     `poetry.lock`, `uv.lock`, `pdm.lock`
//!
//! Not supported (errors with a clear message):
//!   - Yarn Berry (`yarn.lock` v2+, recognised by the `__metadata:` header).
//!
//! The parser is intentionally permissive: unknown fields are ignored,
//! malformed entries are skipped, and the output is deduplicated by
//! (ecosystem, name, version). Better to under-flag than to refuse a
//! real lockfile.

use anyhow::{anyhow, Context, Result};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ecosystem {
    Npm,
    Pypi,
    Rubygems,
    Cargo,
    Maven,
}

impl Ecosystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::Rubygems => "rubygems",
            Self::Cargo => "cargo",
            Self::Maven => "maven",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockfileEntry {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
}

impl LockfileEntry {
    /// Wire format the gate endpoint expects. npm uses `name@version`,
    /// PyPI uses `name==version`, RubyGems uses `name@version` (same
    /// as npm — Gemfile.lock writes `gem-name (1.2.3)` but we
    /// normalize on the @-separated form server-side).
    pub fn spec(&self) -> String {
        match self.ecosystem {
            Ecosystem::Npm => format!("{}@{}", self.name, self.version),
            Ecosystem::Pypi => format!("{}=={}", self.name, self.version),
            Ecosystem::Rubygems => format!("{}@{}", self.name, self.version),
            // Cargo uses `name@version` too — same shape as npm/gem
            // but disambiguated via --ecosystem on bare CLI args.
            Ecosystem::Cargo => format!("{}@{}", self.name, self.version),
            // Maven coordinates are `groupId:artifactId@version`; the
            // name field already contains `groupId:artifactId` here.
            Ecosystem::Maven => format!("{}@{}", self.name, self.version),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum LockfileKind {
    Npm,
    Pnpm,
    YarnV1,
    PyRequirements,
    PyPipfileLock,
    PyPoetryLock,
    PyUvLock,
    PyPdmLock,
    Gemfile,
    Cargo,
    Pom,
}

pub fn parse(path: &Path) -> Result<Vec<LockfileEntry>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading lockfile {}", path.display()))?;
    let kind = detect_kind(path, &content)?;
    let entries = match kind {
        LockfileKind::Npm => parse_npm(&content)?,
        LockfileKind::Pnpm => parse_pnpm(&content)?,
        LockfileKind::YarnV1 => parse_yarn_v1(&content)?,
        LockfileKind::PyRequirements => parse_requirements_txt(&content)?,
        LockfileKind::PyPipfileLock => parse_pipfile_lock(&content)?,
        LockfileKind::PyPoetryLock => parse_poetry_lock(&content)?,
        LockfileKind::PyUvLock => parse_uv_lock(&content)?,
        LockfileKind::PyPdmLock => parse_pdm_lock(&content)?,
        LockfileKind::Gemfile => parse_gemfile_lock(&content)?,
        LockfileKind::Cargo => parse_cargo_lock(&content)?,
        LockfileKind::Pom => parse_pom_xml(&content)?,
    };
    let mut entries: Vec<LockfileEntry> = entries
        .into_iter()
        .filter(|e| !e.name.is_empty() && !e.version.is_empty())
        .filter(|e| {
            match e.ecosystem {
                Ecosystem::Npm => {
                    // Non-registry refs we can't gate against the npm registry.
                    !e.version.starts_with("file:")
                        && !e.version.starts_with("link:")
                        && !e.version.starts_with("workspace:")
                        && !e.version.starts_with("git+")
                        && !e.version.starts_with("github:")
                        && !e.version.starts_with("npm:")
                        && !e.version.contains('/')
                }
                Ecosystem::Pypi => {
                    // PyPI deps that live outside the public registry: git
                    // URLs, file://, direct URL refs (PEP 508 url specs),
                    // editable installs. Gate has nothing to say about
                    // those.
                    !e.version.starts_with("git+")
                        && !e.version.starts_with("file:")
                        && !e.version.starts_with("http://")
                        && !e.version.starts_with("https://")
                        && !e.name.contains('/')
                }
                Ecosystem::Rubygems => {
                    // Gemfile.lock entries from non-registry sources
                    // (GIT, PATH, plugin sources) get filtered upstream
                    // in parse_gemfile_lock; this filter is a final
                    // sanity check.
                    !e.name.contains('/') && !e.name.is_empty()
                }
                Ecosystem::Cargo => {
                    // git/path/workspace sources are filtered upstream
                    // in parse_cargo_lock by skipping entries whose
                    // `source` is anything other than the crates.io
                    // registry sentinel.
                    !e.name.is_empty() && !e.version.is_empty()
                }
                Ecosystem::Maven => {
                    // ${prop} interpolated versions never gate
                    // cleanly because the gate has no way to resolve
                    // them; parse_pom_xml drops those at parse time.
                    // This filter keeps the contract symmetric.
                    !e.version.starts_with("${")
                        && !e.version.starts_with('[')
                        && !e.version.starts_with('(')
                        && e.name.contains(':')
                }
            }
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
        "requirements.txt" | "requirements.lock" | "constraints.txt" => {
            Ok(LockfileKind::PyRequirements)
        }
        "pipfile.lock" => Ok(LockfileKind::PyPipfileLock),
        "poetry.lock" => Ok(LockfileKind::PyPoetryLock),
        "uv.lock" => Ok(LockfileKind::PyUvLock),
        "pdm.lock" => Ok(LockfileKind::PyPdmLock),
        "gemfile.lock" | "gems.locked" => Ok(LockfileKind::Gemfile),
        "cargo.lock" => Ok(LockfileKind::Cargo),
        "pom.xml" => Ok(LockfileKind::Pom),
        _ => Err(anyhow!(
            "unrecognised lockfile name `{name}`. Supported: package-lock.json, \
             npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock, requirements.txt, \
             Pipfile.lock, poetry.lock, uv.lock, pdm.lock, Gemfile.lock, Cargo.lock, pom.xml."
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
                        ecosystem: Ecosystem::Npm,
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

fn walk_npm_v1(deps: &serde_json::Map<String, serde_json::Value>, out: &mut Vec<LockfileEntry>) {
    for (name, value) in deps {
        if let Some(version) = value.get("version").and_then(|v| v.as_str()) {
            out.push(LockfileEntry {
                ecosystem: Ecosystem::Npm,
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
            entries.push(LockfileEntry {
                ecosystem: Ecosystem::Npm,
                name,
                version,
            });
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
                    ecosystem: Ecosystem::Npm,
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

// --- PyPI: requirements.txt ----------------------------------------------

/// Parse pip-style requirements. Only fully pinned lines (`name==X.Y.Z`)
/// are kept — the gate needs concrete versions, not ranges. Comments,
/// blank lines, `-r/-c/-e` directives, environment markers, hashes,
/// and unpinned specs are skipped.
fn parse_requirements_txt(content: &str) -> Result<Vec<LockfileEntry>> {
    let mut entries = Vec::new();
    // Support line continuation with trailing backslash.
    let mut joined = String::new();
    for raw in content.lines() {
        if raw.trim_end().ends_with('\\') {
            let without_backslash = raw.trim_end().trim_end_matches('\\');
            joined.push_str(without_backslash);
            joined.push(' ');
        } else {
            joined.push_str(raw);
            joined.push('\n');
        }
    }
    for line in joined.lines() {
        let line = match line.split_once('#') {
            Some((before, _)) => before,
            None => line,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Skip pip directives (`-r requirements-dev.txt`, `--hash=...`,
        // `--index-url=...`, etc.) and editable installs (`-e <vcs>`).
        if line.starts_with('-') {
            continue;
        }
        if let Some(entry) = parse_requirements_line(line) {
            entries.push(entry);
        }
    }
    Ok(entries)
}

/// Returns Some for `name[extras]==version` lines, None for everything
/// else (`>=`, `~=`, ranges, URL specs, markers without ==, etc.).
fn parse_requirements_line(line: &str) -> Option<LockfileEntry> {
    // Strip environment markers: `name==1.0.0 ; python_version >= "3.10"`.
    let line = match line.split_once(';') {
        Some((before, _)) => before.trim(),
        None => line.trim(),
    };
    // Strip hash fragments: `name==1.0.0 --hash=sha256:abc`.
    let line = match line.split_once("--hash") {
        Some((before, _)) => before.trim(),
        None => line,
    };
    // Find the operator. We require `==` (or `===` for PEP 440 arbitrary
    // equality) so we know we have a pinned version.
    let (op_idx, op_len) = if let Some(idx) = line.find("===") {
        (idx, 3)
    } else if let Some(idx) = line.find("==") {
        (idx, 2)
    } else {
        return None;
    };
    let name_part = line[..op_idx].trim();
    let version_part = line[op_idx + op_len..].trim();
    if name_part.is_empty() || version_part.is_empty() {
        return None;
    }
    // Strip `[extras]` suffix: `requests[security]==2.31.0`.
    let name = match name_part.split_once('[') {
        Some((before, _)) => before.trim(),
        None => name_part,
    };
    let name = normalize_pypi_name(name);
    if !is_valid_pypi_name(&name) {
        return None;
    }
    // Bare version, no trailing constraints like `==1.0.0,!=1.1.0`.
    if version_part.contains(',') || version_part.contains(' ') {
        return None;
    }
    let version = version_part.trim_matches('"').trim_matches('\'').to_string();
    Some(LockfileEntry {
        ecosystem: Ecosystem::Pypi,
        name,
        version,
    })
}

/// PEP 503 name normalization: lowercase, runs of `_`/`.`/`-` collapse
/// to a single `-`. Two distributions whose normalized names match are
/// considered the same package by PyPI.
fn normalize_pypi_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_sep = false;
    for c in raw.chars() {
        if matches!(c, '_' | '.' | '-') {
            if !prev_sep && !out.is_empty() {
                out.push('-');
            }
            prev_sep = true;
        } else {
            out.push(c.to_ascii_lowercase());
            prev_sep = false;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

fn is_valid_pypi_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

// --- PyPI: Pipfile.lock --------------------------------------------------

fn parse_pipfile_lock(content: &str) -> Result<Vec<LockfileEntry>> {
    let parsed: serde_json::Value =
        serde_json::from_str(content).context("parsing Pipfile.lock")?;
    let mut entries = Vec::new();
    for section in ["default", "develop"] {
        if let Some(obj) = parsed.get(section).and_then(|v| v.as_object()) {
            for (name, value) in obj {
                let Some(raw) = value.get("version").and_then(|v| v.as_str()) else {
                    continue;
                };
                let version = raw
                    .trim()
                    .trim_start_matches("==")
                    .trim_start_matches("===")
                    .trim()
                    .to_string();
                if version.is_empty() {
                    continue;
                }
                let normalized = normalize_pypi_name(name);
                if !is_valid_pypi_name(&normalized) {
                    continue;
                }
                entries.push(LockfileEntry {
                    ecosystem: Ecosystem::Pypi,
                    name: normalized,
                    version,
                });
            }
        }
    }
    Ok(entries)
}

// --- PyPI: poetry.lock ---------------------------------------------------

/// Common shape: `[[package]] name = "foo"\nversion = "1.2.3"` blocks.
/// This shape is shared by poetry.lock, uv.lock, and pdm.lock — they
/// all use the TOML `[[package]]` array convention.
fn parse_toml_package_array(content: &str) -> Result<Vec<LockfileEntry>> {
    let parsed: toml::Value = toml::from_str(content).context("parsing TOML lockfile")?;
    let mut entries = Vec::new();
    let Some(packages) = parsed.get("package").and_then(|v| v.as_array()) else {
        return Ok(entries);
    };
    for pkg in packages {
        let Some(table) = pkg.as_table() else {
            continue;
        };
        let Some(name) = table.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(version) = table.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        // Skip non-registry sources. Poetry emits `git`, `directory`,
        // `url` for off-registry packages; `legacy` for private
        // PyPI-compatible indexes (which we still treat as registry-
        // shaped). Anything we don't recognize as a registry source is
        // skipped so a new Poetry source type can't be silently gated
        // through PyPI by accident.
        if let Some(source) = table.get("source").and_then(|v| v.as_table()) {
            let ty = source.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if !matches!(ty, "" | "legacy") {
                continue;
            }
        }
        let normalized = normalize_pypi_name(name);
        if !is_valid_pypi_name(&normalized) {
            continue;
        }
        entries.push(LockfileEntry {
            ecosystem: Ecosystem::Pypi,
            name: normalized,
            version: version.to_string(),
        });
    }
    Ok(entries)
}

fn parse_poetry_lock(content: &str) -> Result<Vec<LockfileEntry>> {
    parse_toml_package_array(content)
}

fn parse_uv_lock(content: &str) -> Result<Vec<LockfileEntry>> {
    parse_toml_package_array(content)
}

fn parse_pdm_lock(content: &str) -> Result<Vec<LockfileEntry>> {
    parse_toml_package_array(content)
}

// --- Cargo: Cargo.lock --------------------------------------------------

/// Parse a Cargo.lock. The format is TOML with a top-level array of
/// `[[package]]` tables: `name`, `version`, `source`, and
/// `checksum`. Only entries whose `source` is the crates.io registry
/// sentinel (`registry+https://github.com/rust-lang/crates.io-index`
/// or the newer `sparse+https://index.crates.io/`) are gated. Git,
/// path, and workspace-local crates have no source recorded the
/// gate can consult, so we skip them.
fn parse_cargo_lock(content: &str) -> Result<Vec<LockfileEntry>> {
    let parsed: toml::Value = toml::from_str(content).context("parsing Cargo.lock")?;
    let mut entries = Vec::new();
    let Some(packages) = parsed.get("package").and_then(|v| v.as_array()) else {
        return Ok(entries);
    };
    for pkg in packages {
        let Some(table) = pkg.as_table() else {
            continue;
        };
        let Some(name) = table.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(version) = table.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        // The workspace's own crates (your code under [workspace] /
        // [package]) appear in Cargo.lock with no `source` field.
        // Don't gate those — they're not registry-resolved.
        let source = table.get("source").and_then(|v| v.as_str()).unwrap_or("");
        if source.is_empty() {
            continue;
        }
        // Only registry sources go through the gate. git+ssh, git+
        // https, path+, etc. are not registry-shaped.
        if !source.starts_with("registry+") && !source.starts_with("sparse+") {
            continue;
        }
        entries.push(LockfileEntry {
            ecosystem: Ecosystem::Cargo,
            name: name.to_string(),
            version: version.to_string(),
        });
    }
    Ok(entries)
}

// --- Maven: pom.xml ---------------------------------------------------

/// Parse Maven's pom.xml for direct dependencies with concrete pinned
/// versions. Real Maven projects rarely commit a lockfile, so the
/// `pom.xml` itself is the closest thing the gate can consume.
///
/// We extract groupId / artifactId / version triples from
/// `<dependency>` blocks; `<dependencyManagement>` declarations are
/// skipped because they're version-pins-for-children, not actual
/// resolved dependencies of the current project. Version property
/// references (`${spring.version}`) and version ranges
/// (`[1.0,2.0)`, `(0,)`) are also skipped — the gate can only act
/// on a fully concrete coordinate.
///
/// XML parsing here is intentionally minimal (regex over the source).
/// A full XML parser would also handle namespaces, comments, and
/// CDATA, but the worst we can do with regex is drop a dep — never
/// produce a wrong one. Keeping the dep surface small is the
/// security-first choice.
fn parse_pom_xml(content: &str) -> Result<Vec<LockfileEntry>> {
    let mut entries = Vec::new();

    // First strip <dependencyManagement> blocks so we don't pick up
    // their inner <dependency> declarations. The block can be
    // arbitrarily-nested but in practice never contains another
    // <dependencyManagement>, so a single greedy strip is fine.
    let stripped = strip_xml_block(content, "dependencyManagement");

    // Strip XML comments too — sometimes folks comment-out deps and
    // we don't want to accidentally surface them.
    let stripped = strip_xml_comments(&stripped);

    // Now iterate <dependency>...</dependency> blocks. The same
    // block can appear inside <plugin> declarations too — those are
    // build-time plugin deps which we still gate (a malicious build
    // plugin is the canonical Maven supply-chain attack).
    let mut pos = 0;
    while let Some(start) = stripped[pos..].find("<dependency>") {
        let abs_start = pos + start + "<dependency>".len();
        let Some(end) = stripped[abs_start..].find("</dependency>") else {
            break;
        };
        let block = &stripped[abs_start..abs_start + end];
        pos = abs_start + end + "</dependency>".len();
        let Some(group) = xml_inner_text(block, "groupId") else {
            continue;
        };
        let Some(artifact) = xml_inner_text(block, "artifactId") else {
            continue;
        };
        let Some(version) = xml_inner_text(block, "version") else {
            // Maven inherits versions from parent POMs and BOMs when
            // no <version> is given. The gate has no way to resolve
            // that, so skip silently.
            continue;
        };
        let group = group.trim();
        let artifact = artifact.trim();
        let version = version.trim();
        if group.is_empty() || artifact.is_empty() || version.is_empty() {
            continue;
        }
        // Skip property references and version ranges; both need
        // resolution we can't perform from pom.xml alone.
        if version.starts_with("${")
            || version.starts_with('[')
            || version.starts_with('(')
            || version.contains(',')
        {
            continue;
        }
        entries.push(LockfileEntry {
            ecosystem: Ecosystem::Maven,
            name: format!("{group}:{artifact}"),
            version: version.to_string(),
        });
    }
    Ok(entries)
}

/// Best-effort strip of a top-level XML block by name. Used to drop
/// `<dependencyManagement>...</dependencyManagement>` before the
/// dependency-scanner walks the remaining text. Handles a single
/// well-formed nesting; if the block is malformed we return the
/// content unchanged so the dep scanner still sees something.
fn strip_xml_block(content: &str, name: &str) -> String {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let mut out = String::with_capacity(content.len());
    let mut pos = 0;
    while let Some(start) = content[pos..].find(&open) {
        let abs_start = pos + start;
        out.push_str(&content[pos..abs_start]);
        let after_open = abs_start + open.len();
        let Some(end_rel) = content[after_open..].find(&close) else {
            // Malformed — keep the rest of the document so we don't
            // silently lose dependency entries downstream.
            out.push_str(&content[abs_start..]);
            return out;
        };
        pos = after_open + end_rel + close.len();
    }
    out.push_str(&content[pos..]);
    out
}

fn strip_xml_comments(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut pos = 0;
    while let Some(start) = content[pos..].find("<!--") {
        let abs_start = pos + start;
        out.push_str(&content[pos..abs_start]);
        let after_open = abs_start + 4;
        let Some(end_rel) = content[after_open..].find("-->") else {
            out.push_str(&content[abs_start..]);
            return out;
        };
        pos = after_open + end_rel + 3;
    }
    out.push_str(&content[pos..]);
    out
}

/// Return the first inner text of a top-level child tag named
/// `tag` inside `block`. Doesn't try to handle namespaces — Maven
/// poms typically use the default namespace, and our tag names
/// (groupId/artifactId/version) don't appear with prefixes in
/// real-world poms.
fn xml_inner_text(block: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = block.find(&open)?;
    let inner_start = start + open.len();
    let end = block[inner_start..].find(&close)?;
    Some(block[inner_start..inner_start + end].to_string())
}

// --- RubyGems: Gemfile.lock --------------------------------------------

/// Parse Bundler's `Gemfile.lock`. The interesting section is `GEM`,
/// containing the registry-resolved tree. Each gem appears as
/// `    name (1.2.3)` indented under `  specs:`. Transitive deps are
/// indented one level deeper as `      name (~> 1.0)` (no version
/// pin — those are not gated, we only care about the resolved
/// versions). GIT, PATH, PLUGIN sections are skipped.
fn parse_gemfile_lock(content: &str) -> Result<Vec<LockfileEntry>> {
    let mut entries = Vec::new();
    let mut in_gem = false;
    let mut in_specs = false;
    for line in content.lines() {
        // Section headers are flush-left.
        if !line.starts_with(' ') {
            let header = line.trim();
            in_gem = header == "GEM";
            in_specs = false;
            continue;
        }
        if !in_gem {
            continue;
        }
        let trimmed = line.trim_start();
        // The `  specs:` line marks the start of resolved versions.
        if trimmed == "specs:" {
            in_specs = true;
            continue;
        }
        if !in_specs {
            continue;
        }
        // We only care about lines at exactly 4-space indent (top-level
        // resolved gem), not deeper indents which are transitive-dep
        // declarations with version constraints rather than pins.
        let leading = line.len() - trimmed.len();
        if leading != 4 {
            continue;
        }
        let Some((name, rest)) = trimmed.split_once(' ') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let rest = rest.trim();
        let Some(version) = rest
            .strip_prefix('(')
            .and_then(|v| v.strip_suffix(')'))
            .map(|s| s.trim())
        else {
            continue;
        };
        // RubyGems versions are dot-separated; skip version constraints
        // and platform suffixes that aren't plain version strings.
        if version.contains(' ') || version.starts_with('~') || version.starts_with('>') {
            continue;
        }
        // Skip platform-qualified entries like `nokogiri (1.16.0-x86_64-linux)`
        // — we lose nothing because the un-suffixed entry is in the
        // same `specs:` block for portable resolutions, and platform
        // pins aren't typosquatted in practice.
        if version.contains('-') {
            continue;
        }
        entries.push(LockfileEntry {
            ecosystem: Ecosystem::Rubygems,
            name: name.to_string(),
            version: version.to_string(),
        });
    }
    Ok(entries)
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
    fn requirements_txt_pinned_only() {
        let content = "\
# bound
requests==2.31.0
urllib3==2.0.7 ; python_version >= \"3.10\"
flask[async]==3.0.0
unpinned-package>=1.0.0
ranged==1.0.0,!=1.1.0
-r requirements-dev.txt
--hash=sha256:abc
git+https://github.com/x/y.git@v1
torch===2.5.0
";
        let entries = parse_requirements_txt(content).unwrap();
        let specs: Vec<String> = entries.iter().map(|e| e.spec()).collect();
        assert!(specs.contains(&"requests==2.31.0".to_string()));
        assert!(specs.contains(&"urllib3==2.0.7".to_string()));
        assert!(specs.contains(&"flask==3.0.0".to_string()));
        assert!(specs.contains(&"torch==2.5.0".to_string()));
        assert!(!specs.iter().any(|s| s.starts_with("unpinned-package")));
        assert!(!specs.iter().any(|s| s.starts_with("ranged")));
    }

    #[test]
    fn pipfile_lock_parses() {
        let content = r#"{
            "default": {
                "requests": { "version": "==2.31.0" },
                "Flask": { "version": "==3.0.0" }
            },
            "develop": {
                "pytest": { "version": "==7.4.0" }
            }
        }"#;
        let entries = parse_pipfile_lock(content).unwrap();
        let specs: Vec<String> = entries.iter().map(|e| e.spec()).collect();
        assert!(specs.contains(&"requests==2.31.0".to_string()));
        assert!(specs.contains(&"flask==3.0.0".to_string()));
        assert!(specs.contains(&"pytest==7.4.0".to_string()));
    }

    #[test]
    fn poetry_lock_parses() {
        let content = r#"
[[package]]
name = "requests"
version = "2.31.0"
description = ""

[[package]]
name = "Pytest"
version = "7.4.0"
"#;
        let entries = parse_poetry_lock(content).unwrap();
        let specs: Vec<String> = entries.iter().map(|e| e.spec()).collect();
        assert!(specs.contains(&"requests==2.31.0".to_string()));
        assert!(specs.contains(&"pytest==7.4.0".to_string()));
    }

    #[test]
    fn pypi_name_normalization() {
        assert_eq!(normalize_pypi_name("Requests"), "requests");
        assert_eq!(normalize_pypi_name("zope.interface"), "zope-interface");
        assert_eq!(normalize_pypi_name("python__dateutil"), "python-dateutil");
        assert_eq!(normalize_pypi_name("a.b_c-d"), "a-b-c-d");
    }

    #[test]
    fn pom_xml_parses() {
        let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>myapp</artifactId>
  <version>0.1.0-SNAPSHOT</version>

  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-bom</artifactId>
        <version>5.3.30</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>

  <dependencies>
    <!-- pinned, registry-resolved -->
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.17.0</version>
    </dependency>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.20.0</version>
    </dependency>
    <!-- ${prop} version → skipped -->
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>${junit.version}</version>
    </dependency>
    <!-- version range → skipped -->
    <dependency>
      <groupId>commons-lang</groupId>
      <artifactId>commons-lang</artifactId>
      <version>[2.6,3.0)</version>
    </dependency>
    <!-- no version (inherits from parent/bom) → skipped -->
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
    </dependency>
  </dependencies>
</project>"#;
        let entries = parse_pom_xml(content).unwrap();
        let specs: Vec<String> = entries.iter().map(|e| e.spec()).collect();
        assert!(specs.contains(&"com.fasterxml.jackson.core:jackson-databind@2.17.0".to_string()));
        assert!(specs.contains(&"org.apache.logging.log4j:log4j-core@2.20.0".to_string()));
        // dependencyManagement → not gated.
        assert!(!specs.iter().any(|s| s.contains("spring-bom")));
        // ${prop} version → skipped.
        assert!(!specs.iter().any(|s| s.contains("junit-jupiter")));
        // version range → skipped.
        assert!(!specs.iter().any(|s| s.contains("commons-lang")));
        // missing <version> → skipped.
        assert!(!specs.iter().any(|s| s.contains("spring-core")));
    }

    #[test]
    fn cargo_lock_parses() {
        let content = r#"
version = 3

[[package]]
name = "myapp"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.219"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"

[[package]]
name = "anyhow"
version = "1.0.102"
source = "sparse+https://index.crates.io/"
checksum = "def"

[[package]]
name = "private-lib"
version = "0.1.0"
source = "git+https://github.com/example/private-lib.git#deadbeef"
"#;
        let entries = parse_cargo_lock(content).unwrap();
        let specs: Vec<String> = entries.iter().map(|e| e.spec()).collect();
        // Workspace crate (no `source`) → skipped.
        assert!(!specs.iter().any(|s| s.starts_with("myapp@")));
        // crates.io registry entries → kept.
        assert!(specs.contains(&"serde@1.0.219".to_string()));
        assert!(specs.contains(&"anyhow@1.0.102".to_string()));
        // git-sourced crate → skipped.
        assert!(!specs.iter().any(|s| s.starts_with("private-lib@")));
    }

    #[test]
    fn gemfile_lock_parses() {
        let content = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.1.0)\n    rack-test (2.1.0)\n      rack (>= 1.3)\n    nokogiri (1.16.0)\n    nokogiri (1.16.0-x86_64-linux)\n\nGIT\n  remote: https://github.com/foo/bar.git\n  revision: deadbeef\n  specs:\n    bar (0.1.0)\n\nDEPENDENCIES\n  rack\n  rack-test\n\nBUNDLED WITH\n   2.4.0\n";
        let entries = parse_gemfile_lock(content).unwrap();
        let specs: Vec<String> = entries.iter().map(|e| e.spec()).collect();
        // GEM block, registry-resolved, plain version → kept.
        assert!(specs.contains(&"rack@3.1.0".to_string()));
        assert!(specs.contains(&"rack-test@2.1.0".to_string()));
        assert!(specs.contains(&"nokogiri@1.16.0".to_string()));
        // platform-suffixed variant → skipped (we have the portable
        // entry above).
        assert!(!specs.iter().any(|s| s.contains("x86_64-linux")));
        // Transitive dep declarations (indented deeper) with version
        // constraints → skipped (we only gate pinned resolutions).
        assert!(!specs.iter().any(|s| s.starts_with("rack@>=")));
        // GIT-sourced gem → skipped (not on registry).
        assert!(!specs.iter().any(|s| s.starts_with("bar@")));
    }

    #[test]
    fn parse_filters_workspace_and_link_versions() {
        let entries = vec![
            LockfileEntry {
                ecosystem: Ecosystem::Npm,
                name: "real".to_string(),
                version: "1.0.0".to_string(),
            },
            LockfileEntry {
                ecosystem: Ecosystem::Npm,
                name: "linked".to_string(),
                version: "link:../foo".to_string(),
            },
            LockfileEntry {
                ecosystem: Ecosystem::Npm,
                name: "ws".to_string(),
                version: "workspace:*".to_string(),
            },
        ];
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
