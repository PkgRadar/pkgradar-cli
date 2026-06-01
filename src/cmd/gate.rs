use anyhow::{anyhow, Result};
use clap::Args;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use crate::client::{AuthRejected, BlockedItem, Client, GateResponse};
use crate::cmd::CommonArgs;
use crate::config;
use crate::lockfile::{self, Ecosystem};

#[derive(Args, Debug)]
pub struct GateArgs {
    /// One or more package specs, e.g. `lodash@4.17.21` (npm),
    /// `requests==2.31.0` (PyPI), or `rails@8.0.0` (RubyGems with
    /// --ecosystem rubygems). Ecosystem is inferred from the version
    /// separator (`==` → PyPI) unless `--ecosystem` overrides.
    /// Optional when `--lockfile` is provided.
    #[arg(num_args = 0..)]
    pub specs: Vec<String>,

    /// Force the ecosystem for positional specs. npm, rubygems,
    /// cargo, and maven all use the `name@version` format so when
    /// ambiguous, this is how you disambiguate (maven specs are
    /// `groupId:artifactId@version`).
    #[arg(long, value_parser = ["npm", "pypi", "rubygems", "cargo", "maven", "nuget", "composer"])]
    pub ecosystem: Option<String>,

    /// Block when a spec's risk is at or above this level. Overrides the
    /// `fail_on` value in `.pkgradar.yml` if both are present.
    #[arg(long, value_parser = ["high", "review", "low"])]
    pub fail_on: Option<String>,

    /// Opt in to ALSO failing the build on known-vulnerability advisories
    /// (plain CVEs) at or above this severity. Off by default — advisories
    /// are shown as warnings but don't block, because a vulnerable-but-
    /// legitimate dependency is not a supply-chain attack. Use this if you
    /// want npm-audit-style CVE gating in the same step.
    #[arg(long, value_parser = ["low", "moderate", "high", "critical"])]
    pub fail_on_cve: Option<String>,

    /// Path to a lockfile to gate. Repeatable — pass `--lockfile` multiple
    /// times for a polyglot/monorepo (e.g. `--lockfile frontend/package-lock.json
    /// --lockfile api/requirements.txt`). When omitted (and no positional
    /// specs are given), PkgRadar RECURSIVELY DISCOVERS every supported
    /// lockfile in the working tree and gates them all.
    #[arg(long)]
    pub lockfile: Vec<PathBuf>,

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

    // Off unless explicitly requested (flag or config). When unset, the
    // server treats advisories as informational only.
    let fail_on_cve = args.fail_on_cve.clone().or_else(|| cfg.fail_on_cve.clone());

    let timeout_ms = if args.common.timeout_ms != 60000 {
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
        let bucket = buckets.entry(eco).or_insert_with(|| EcosystemBucket {
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
        "maven" => Some(Ecosystem::Maven),
        "nuget" => Some(Ecosystem::Nuget),
        "composer" => Some(Ecosystem::Composer),
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
    // Resolve which lockfiles to read:
    //   - explicit `--lockfile` (one or more)  -> exactly those (a bad path
    //     is a hard error; the user named it).
    //   - else if positional specs were given  -> none (specs-only mode).
    //   - else                                 -> recursively discover every
    //     supported lockfile in the tree. This is what stops the silent
    //     "green pass over a near-empty root lockfile" footgun: a polyglot
    //     repo (frontend/package-lock.json + api/requirements.txt) is fully
    //     covered without N hand-written steps.
    let explicit_lockfiles = !args.lockfile.is_empty();
    let specs_only = args
        .specs
        .iter()
        .chain(cfg.watchlist.iter())
        .next()
        .is_some();
    let discovery_mode = !explicit_lockfiles && !specs_only;

    let lockfiles: Vec<PathBuf> = if explicit_lockfiles {
        args.lockfile.clone()
    } else if discovery_mode {
        lockfile::discover(Path::new("."), 8)
    } else {
        Vec::new()
    };

    // Discovery that finds nothing is an ERROR, not a pass. A silent exit-0
    // on zero coverage is indistinguishable from "your project is clean" —
    // the exact failure mode that hid a polyglot repo's whole surface.
    if discovery_mode && lockfiles.is_empty() {
        return Err(anyhow!(
            "no lockfile found in the working tree. Pass --lockfile <path> \
             (repeatable), give explicit specs, or run from a directory \
             containing a supported lockfile (package-lock.json, \
             pnpm-lock.yaml, yarn.lock, requirements.txt, poetry.lock, \
             uv.lock, Gemfile.lock, Cargo.lock, pom.xml, composer.lock, …)."
        ));
    }

    // Parse each lockfile and print its resolved path + spec count, so
    // coverage is explicit rather than deduced from a final tally.
    for path in &lockfiles {
        match lockfile::parse(path) {
            Ok(entries) => {
                let n = entries.len();
                if !args.common.quiet {
                    eprintln!("pkgradar: {} — {} package(s)", path.display(), n);
                }
                for entry in entries {
                    record(eco_from_lockfile(entry.ecosystem), entry.spec());
                }
            }
            Err(err) => {
                if explicit_lockfiles {
                    // The user named this file; refusing to parse it is a
                    // hard error, not a silent skip.
                    return Err(err.context(format!("lockfile {}", path.display())));
                }
                // Discovered (not user-named): a stray/unsupported file
                // shouldn't fail the whole run — warn and move on.
                eprintln!("pkgradar: skipping {} ({err:#})", path.display());
            }
        }
    }

    let total_specs: usize = buckets.values().map(|b| b.specs.len()).sum();
    let total_allowlisted: usize = buckets.values().map(|b| b.allowlisted.len()).sum();
    if total_specs == 0 {
        // Reached only via explicit --lockfile / specs that resolved to
        // nothing gateable (all entries filtered: git/file/workspace refs,
        // etc.). Surface it loudly; discovery-found-nothing already errored.
        eprintln!(
            "pkgradar: nothing to gate — every entry was filtered (git/file/workspace \
             refs or non-registry sources). Coverage is effectively zero; check the \
             lockfile path(s) above."
        );
        return Ok(0);
    }

    let client = Client::new(args.common.base_url, args.common.token, timeout_ms)?;
    let mut combined_allowed = true;
    let mut combined_blocked: Vec<BlockedItem> = Vec::new();
    let mut combined_reports: Vec<Value> = Vec::new();
    let mut last_fail_on = fail_on.clone();

    // The gate endpoint caps each request at GATE_BATCH specs (tuned to the
    // server-side scan concurrency + the per-request timeout), so a real
    // lockfile must be sent in chunks. Sending the whole bucket in one call
    // previously tripped a 413 and — with fail-open — silently passed the
    // entire build unchecked.
    const GATE_BATCH: usize = 25;
    // When a batch call fails (typically a cold cargo/maven batch exceeding
    // the request timeout on a busy server), retry by HALVING it down to
    // this size before fail-opening. A slow 25-batch becomes 12+13 — usually
    // both succeed — so worst-case unchecked coverage drops from a whole
    // batch to <=MIN. Without this, fail-open silently skips all 25 (a
    // partial "green" that looks fully checked).
    const MIN_RETRY_CHUNK: usize = 5;
    // Bound total splits per run so a HARD outage (every call failing) fails
    // open fast instead of fanning each batch into ~log2(N) doomed retries
    // and making CI hang. Generous enough to rescue several slow batches.
    let mut split_budget: i32 = 16;
    let mut fail_open_skipped = 0usize;
    for (ecosystem, bucket) in &buckets {
        if bucket.specs.is_empty() {
            continue;
        }
        // LIFO work queue: a failed large chunk is split and re-queued.
        let mut queue: Vec<Vec<String>> =
            bucket.specs.chunks(GATE_BATCH).map(<[_]>::to_vec).collect();
        while let Some(chunk) = queue.pop() {
            let response = match client
                .gate(ecosystem.as_str(), &chunk, &fail_on, fail_on_cve.as_deref())
                .await
            {
                Ok(r) => r,
                Err(err) => {
                    // A rejected token is a config error, not a transient
                    // outage — NEVER fail-open on it (that's how a wrong token
                    // passes a build having scanned nothing). Abort the whole
                    // gate loudly so the failure is impossible to miss.
                    if err.downcast_ref::<AuthRejected>().is_some() {
                        return Err(err.context(
                            "gate aborted — API token rejected; NOTHING was scanned. \
                             Fix PKGRADAR_TOKEN (re-copy from the dashboard; watch for a \
                             stray newline). Not fail-opened: an invalid token is a \
                             configuration error, not a transient outage.",
                        ));
                    }
                    if chunk.len() > MIN_RETRY_CHUNK && split_budget > 0 {
                        // Slow/large batch — retry smaller rather than skip.
                        split_budget -= 1;
                        let mid = chunk.len() / 2;
                        if !args.common.quiet {
                            eprintln!(
                                "pkgradar: {} batch of {} failed ({err:#}); retrying as {}+{}.",
                                ecosystem.as_str(),
                                chunk.len(),
                                mid,
                                chunk.len() - mid
                            );
                        }
                        queue.push(chunk[mid..].to_vec());
                        queue.push(chunk[..mid].to_vec());
                        continue;
                    } else if fail_open {
                        eprintln!(
                            "pkgradar: gate call for {} ({} spec(s)) failed ({err:#}); \
                             fail-open enabled — these specs were NOT checked. Other batches \
                             still gate. Set `fail_open: false` / --no-fail-open to fail instead.",
                            ecosystem.as_str(),
                            chunk.len()
                        );
                        fail_open_skipped += chunk.len();
                        continue;
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
    }
    if fail_open_skipped > 0 && !args.common.quiet {
        eprintln!(
            "pkgradar: warning — {fail_open_skipped} spec(s) were not checked (fail-open); \
             results below are partial."
        );
    }

    let merged = GateResponse {
        allowed: combined_allowed,
        fail_on: last_fail_on,
        blocked: combined_blocked,
        reports: combined_reports,
    };

    match args.common.format.as_str() {
        "json" => println!("{}", serde_json::to_string_pretty(&render_json(&merged))?),
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
            println!("{mark} [{ecosystem:<4}] {target:<48} risk={risk:<7} score={score}");
        }

        // Advisory-only CVEs: surface them as a non-blocking warning so a
        // developer sees a known-vulnerable dependency even when the gate
        // passes it. (If --fail-on-cve is set, the spec is already in the
        // blocked list and printed below.)
        if !is_blocked {
            let advs = report.get("advisories").and_then(Value::as_array);
            if let Some(advs) = advs.filter(|a| !a.is_empty()) {
                let ids: Vec<&str> = advs
                    .iter()
                    .filter_map(|a| a.get("id").and_then(Value::as_str))
                    .collect();
                let shown = ids.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
                let extra = ids.len().saturating_sub(5);
                let suffix = if extra > 0 {
                    format!(" (+{extra} more)")
                } else {
                    String::new()
                };
                println!(
                    "      \u{26a0} {n} known CVE advisory(ies) — not blocking: {shown}{suffix}",
                    n = advs.len()
                );
            }
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
