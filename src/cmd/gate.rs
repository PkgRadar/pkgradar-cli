use anyhow::Result;
use clap::Args;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

use crate::client::{BlockedItem, Client, GateResponse};
use crate::cmd::CommonArgs;
use crate::lockfile::{self, Ecosystem};
use crate::config;

#[derive(Args, Debug)]
pub struct GateArgs {
    /// One or more package specs, e.g. `lodash@4.17.21` (npm),
    /// `requests==2.31.0` (PyPI), or `rails@8.0.0` (RubyGems with
    /// --ecosystem rubygems). Ecosystem is inferred from the version
    /// separator (`==` → PyPI) unless `--ecosystem` overrides.
    /// Optional when `--lockfile` is provided.
    #[arg(num_args = 0..)]
    pub specs: Vec<String>,

    /// Force the ecosystem for positional specs. npm, rubygems, and
    /// cargo all use the `name@version` format so when ambiguous,
    /// this is how you disambiguate.
    #[arg(long, value_parser = ["npm", "pypi", "rubygems", "cargo"])]
    pub ecosystem: Option<String>,

    /// Block when a spec's risk is at or above this level. Overrides the
    /// `fail_on` value in `.pkgradar.yml` if both are present.
    #[arg(long, value_parser = ["high", "review", "low"])]
    pub fail_on: Option<String>,

    /// Path to a lockfile to scan in addition to (or instead of) `<specs>`.
    /// Auto-detects npm / pnpm / yarn-classic / pip / pipenv / poetry /
    /// uv / pdm / Gemfile.lock by filename.
    #[arg(long)]
    pub lockfile: Option<PathBuf>,

    /// Path to a `.pkgradar.yml` config file. Defaults to `.pkgradar.yml`
    /// in the current directory if it exists.
    #[arg(long)]
    pub config: Option<String>,

    /// Disable fail-open behaviour: any API error (timeout, network, 5xx)
    /// will exit 3 instead of 0. Default is fail-open enabled.
    #[arg(long)]
    pub no_fail_open: bool,

    #[command(flatten)]
    pub common: CommonArgs,
}

/// Bucket of specs that all hit the same `/gate/{ecosystem}` endpoint.
struct EcosystemBucket {
    specs: Vec<String>,
    allowlisted: HashSet<String>,
}

pub async fn run(args: GateArgs) -> Result<i32> {
    let cfg_path = config::resolve_path(args.config.as_deref());
    let cfg = config::load(cfg_path.as_deref())?;

    let fail_on = args
        .fail_on
        .clone()
        .or_else(|| cfg.fail_on.clone())
        .unwrap_or_else(|| "high".to_string());

    let timeout_ms = if args.common.timeout_ms != 8000 {
        args.common.timeout_ms
    } else {
        cfg.timeout_ms.unwrap_or(args.common.timeout_ms)
    };

    let fail_open = if args.no_fail_open {
        false
    } else {
        cfg.fail_open.unwrap_or(true)
    };

    let allow: HashSet<String> = cfg.allowlist.iter().cloned().collect();

    // Collect all candidate (ecosystem, spec) pairs, deduplicate, drop
    // allowlisted specs, and finally bucket them per ecosystem.
    let mut seen: HashSet<(Ecosystem, String)> = HashSet::new();
    let mut buckets: BTreeMap<Ecosystem, EcosystemBucket> = BTreeMap::new();

    let mut record = |eco: Ecosystem, spec: String| {
        if spec.is_empty() {
            return;
        }
        let bucket = buckets
            .entry(eco)
            .or_insert_with(|| EcosystemBucket {
                specs: Vec::new(),
                allowlisted: HashSet::new(),
            });
        if allow.contains(&spec) {
            bucket.allowlisted.insert(spec);
            return;
        }
        if seen.insert((eco, spec.clone())) {
            bucket.specs.push(spec);
        }
    };

    // Positional CLI specs + watchlist: --ecosystem flag wins; else
    // classify by version separator format. RubyGems shares the
    // `name@version` shape with npm so without the flag we'd
    // ambiguously route to npm by default.
    let cli_ecosystem = args.ecosystem.as_deref().and_then(|e| match e {
        "npm" => Some(Ecosystem::Npm),
        "pypi" => Some(Ecosystem::Pypi),
        "rubygems" => Some(Ecosystem::Rubygems),
        "cargo" => Some(Ecosystem::Cargo),
        _ => None,
    });
    for raw in args.specs.iter().chain(cfg.watchlist.iter()) {
        let (eco, spec) = if let Some(forced) = cli_ecosystem {
            (forced, raw.trim().to_string())
        } else {
            classify_cli_spec(raw)
        };
        record(eco, spec);
    }
    if let Some(path) = &args.lockfile {
        for entry in lockfile::parse(path)? {
            record(eco_from_lockfile(entry.ecosystem), entry.spec());
        }
    }

    let total_specs: usize = buckets.values().map(|b| b.specs.len()).sum();
    let total_allowlisted: usize = buckets.values().map(|b| b.allowlisted.len()).sum();
    if total_specs == 0 {
        if !args.common.quiet {
            eprintln!(
                "pkgradar: nothing to gate (no specs provided and lockfile/allowlist filtered everything)."
            );
        }
        return Ok(0);
    }

    let client = Client::new(args.common.base_url, args.common.token, timeout_ms)?;
    let mut combined_allowed = true;
    let mut combined_blocked: Vec<BlockedItem> = Vec::new();
    let mut combined_reports: Vec<Value> = Vec::new();
    let mut last_fail_on = fail_on.clone();

    for (ecosystem, bucket) in &buckets {
        if bucket.specs.is_empty() {
            continue;
        }
        let response = match client
            .gate(ecosystem.as_str(), &bucket.specs, &fail_on)
            .await
        {
            Ok(r) => r,
            Err(err) => {
                if fail_open {
                    eprintln!(
                        "pkgradar: gate API call for {} failed ({err:#}); fail-open enabled, exiting 0. \
                         Set `fail_open: false` in .pkgradar.yml or pass --no-fail-open to harden.",
                        ecosystem.as_str()
                    );
                    return Ok(0);
                } else {
                    return Err(err);
                }
            }
        };
        if !response.allowed {
            combined_allowed = false;
        }
        last_fail_on = response.fail_on.clone();
        // Tag each report with its ecosystem if the server didn't (for
        // older API versions that didn't echo the field back).
        for mut r in response.reports {
            if r.get("ecosystem").is_none() {
                if let Some(obj) = r.as_object_mut() {
                    obj.insert(
                        "ecosystem".to_string(),
                        Value::String(ecosystem.as_str().to_string()),
                    );
                }
            }
            combined_reports.push(r);
        }
        combined_blocked.extend(response.blocked);
    }

    let merged = GateResponse {
        allowed: combined_allowed,
        fail_on: last_fail_on,
        blocked: combined_blocked,
        reports: combined_reports,
    };

    match args.common.format.as_str() {
        "json" => println!(
            "{}",
            serde_json::to_string_pretty(&render_json(&merged))?
        ),
        _ => render_text(&merged, args.common.quiet, total_allowlisted),
    }

    Ok(if merged.allowed { 0 } else { 1 })
}

/// Maps lockfile ecosystem enum to the CLI's local enum. (They share a
/// shape but live in different modules so the renderer can stay
/// agnostic.)
fn eco_from_lockfile(eco: Ecosystem) -> Ecosystem {
    eco
}

/// Classify a bare CLI spec by its version separator: `==` → PyPI,
/// otherwise npm-style `@`. Conservative — anything ambiguous falls back
/// to npm so existing v0.1.0 invocations keep working.
fn classify_cli_spec(raw: &str) -> (Ecosystem, String) {
    let trimmed = raw.trim().to_string();
    if trimmed.contains("==") {
        (Ecosystem::Pypi, trimmed)
    } else {
        (Ecosystem::Npm, trimmed)
    }
}

fn render_json(response: &GateResponse) -> Value {
    serde_json::json!({
        "allowed": response.allowed,
        "fail_on": response.fail_on,
        "blocked": response.blocked.iter().map(blocked_to_json).collect::<Vec<_>>(),
        "decisions": response.reports.iter().map(report_to_decision).collect::<Vec<_>>(),
    })
}

fn blocked_to_json(b: &BlockedItem) -> Value {
    serde_json::json!({
        "target": b.target,
        "risk": b.risk,
        "score": b.score,
        "summary": b.summary,
    })
}

fn report_to_decision(report: &Value) -> Value {
    serde_json::json!({
        "target": report.get("target").and_then(Value::as_str),
        "ecosystem": report.get("ecosystem").and_then(Value::as_str),
        "risk": report.get("risk").and_then(Value::as_str),
        "score": report.get("score").and_then(Value::as_u64),
    })
}

fn render_text(response: &GateResponse, quiet: bool, allowlisted: usize) {
    let blocked_specs: HashSet<&str> = response.blocked.iter().map(|b| b.target.as_str()).collect();

    for report in &response.reports {
        let target = report
            .get("target")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>");
        let risk = report
            .get("risk")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let score = report.get("score").and_then(Value::as_u64).unwrap_or(0);
        let ecosystem = report
            .get("ecosystem")
            .and_then(Value::as_str)
            .unwrap_or("npm");
        let is_blocked = blocked_specs.contains(target);
        let mark = if is_blocked { "BLOCK" } else { "PASS " };

        if is_blocked || !quiet {
            println!(
                "{mark} [{ecosystem:<4}] {target:<48} risk={risk:<7} score={score}"
            );
        }
    }

    for b in &response.blocked {
        if let Some(summary) = b.summary.as_deref() {
            println!("      {target}: {summary}", target = b.target);
        }
    }

    if !response.allowed {
        eprintln!();
        eprintln!(
            "pkgradar: gate blocked {n} of {total} (fail_on={fail_on}).",
            n = response.blocked.len(),
            total = response.reports.len(),
            fail_on = response.fail_on,
        );
    } else if !quiet {
        eprintln!();
        eprintln!(
            "pkgradar: {n} specs passed{extra}.",
            n = response.reports.len(),
            extra = if allowlisted > 0 {
                format!(" ({allowlisted} skipped via allowlist)")
            } else {
                String::new()
            },
        );
    }
}
