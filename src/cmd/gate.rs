use anyhow::Result;
use clap::Args;
use serde_json::Value;
use std::collections::HashSet;
use std::path::PathBuf;

use crate::client::{BlockedItem, Client, GateResponse};
use crate::cmd::CommonArgs;
use crate::{config, lockfile};

#[derive(Args, Debug)]
pub struct GateArgs {
    /// One or more npm package specs, e.g. `lodash@4.17.21`. Optional when
    /// `--lockfile` is provided.
    #[arg(num_args = 0..)]
    pub specs: Vec<String>,

    /// Block when a spec's risk is at or above this level. Overrides the
    /// `fail_on` value in `.pkgradar.yml` if both are present.
    #[arg(long, value_parser = ["high", "review", "low"])]
    pub fail_on: Option<String>,

    /// Path to a lockfile to scan in addition to (or instead of) `<specs>`.
    /// Auto-detects npm / pnpm / yarn-classic by filename.
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

    let mut specs: Vec<String> = args.specs.clone();
    if let Some(path) = &args.lockfile {
        let entries = lockfile::parse(path)?;
        for entry in entries {
            specs.push(entry.spec());
        }
    }
    for s in &cfg.watchlist {
        specs.push(s.clone());
    }

    let allow: HashSet<String> = cfg.allowlist.iter().cloned().collect();
    let mut deduped: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for spec in specs {
        if allow.contains(&spec) {
            continue;
        }
        if seen.insert(spec.clone()) {
            deduped.push(spec);
        }
    }

    if deduped.is_empty() {
        if !args.common.quiet {
            eprintln!(
                "pkgradar: nothing to gate (no specs provided and lockfile/allowlist filtered everything)."
            );
        }
        return Ok(0);
    }

    let client = Client::new(args.common.base_url, args.common.token, timeout_ms)?;
    let response = match client.gate(&deduped, &fail_on).await {
        Ok(r) => r,
        Err(err) => {
            if fail_open {
                eprintln!(
                    "pkgradar: gate API call failed ({err:#}); fail-open enabled, exiting 0. \
                     Set `fail_open: false` in .pkgradar.yml or pass --no-fail-open to harden."
                );
                return Ok(0);
            } else {
                return Err(err);
            }
        }
    };

    match args.common.format.as_str() {
        "json" => println!(
            "{}",
            serde_json::to_string_pretty(&render_json(&response))?
        ),
        _ => render_text(&response, args.common.quiet, allow.len()),
    }

    Ok(if response.allowed { 0 } else { 1 })
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
        "risk": report.get("risk").and_then(Value::as_str),
        "score": report.get("score").and_then(Value::as_u64),
    })
}

fn render_text(response: &GateResponse, quiet: bool, allowlisted: usize) {
    let blocked_specs: HashSet<&str> =
        response.blocked.iter().map(|b| b.target.as_str()).collect();

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
        let is_blocked = blocked_specs.contains(target);
        let mark = if is_blocked { "BLOCK" } else { "PASS " };

        if is_blocked {
            println!("{mark} {target:<48} risk={risk:<6} score={score}");
        } else if !quiet {
            println!("{mark} {target:<48} risk={risk:<6} score={score}");
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
