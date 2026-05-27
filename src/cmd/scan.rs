use anyhow::Result;
use clap::Args;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

use crate::client::Client;
use crate::cmd::CommonArgs;
use crate::lockfile::{self, Ecosystem};

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// One or more package specs (npm `name@version`, PyPI
    /// `name==version`, or RubyGems `name@version`). Ecosystem
    /// inferred from format unless `--ecosystem` overrides.
    #[arg(num_args = 0..)]
    pub specs: Vec<String>,

    /// Force the ecosystem for positional specs. npm, rubygems,
    /// cargo, and maven all use `name@version` shape, so this
    /// disambiguates. (Maven specs look like `group:artifact@version`.)
    #[arg(long, value_parser = ["npm", "pypi", "rubygems", "cargo", "maven"])]
    pub ecosystem: Option<String>,

    /// Path to a lockfile to scan. Auto-detects npm, pnpm, yarn-classic,
    /// pip, pipenv, poetry, uv, pdm, Gemfile.lock by filename.
    #[arg(long)]
    pub lockfile: Option<PathBuf>,

    #[command(flatten)]
    pub common: CommonArgs,
}

pub async fn run(args: ScanArgs) -> Result<i32> {
    // Bucket specs per ecosystem so we can fan out to one /scan/{eco}
    // call each — mirrors the gate command's dispatch.
    let mut buckets: BTreeMap<Ecosystem, Vec<String>> = BTreeMap::new();
    let mut seen: HashSet<(Ecosystem, String)> = HashSet::new();

    let mut record = |eco: Ecosystem, spec: String| {
        if spec.is_empty() {
            return;
        }
        if seen.insert((eco, spec.clone())) {
            buckets.entry(eco).or_default().push(spec);
        }
    };

    let cli_ecosystem = args.ecosystem.as_deref().and_then(|e| match e {
        "npm" => Some(Ecosystem::Npm),
        "pypi" => Some(Ecosystem::Pypi),
        "rubygems" => Some(Ecosystem::Rubygems),
        "cargo" => Some(Ecosystem::Cargo),
        "maven" => Some(Ecosystem::Maven),
        _ => None,
    });
    for raw in &args.specs {
        let (eco, spec) = if let Some(forced) = cli_ecosystem {
            (forced, raw.trim().to_string())
        } else {
            classify_cli_spec(raw)
        };
        record(eco, spec);
    }
    if let Some(path) = &args.lockfile {
        for entry in lockfile::parse(path)? {
            record(entry.ecosystem, entry.spec());
        }
    }

    if buckets.is_empty() {
        return Err(anyhow::anyhow!(
            "no specs provided. Pass --lockfile <path> or one or more `name@version` / `name==version` args."
        ));
    }

    let client = Client::new(
        args.common.base_url,
        args.common.token,
        args.common.timeout_ms,
    )?;

    let mut all_reports: Vec<Value> = Vec::new();
    for (ecosystem, specs) in &buckets {
        let response = client.scan(ecosystem.as_str(), specs).await?;
        for mut r in response.reports {
            if r.get("ecosystem").is_none() {
                if let Some(obj) = r.as_object_mut() {
                    obj.insert(
                        "ecosystem".to_string(),
                        Value::String(ecosystem.as_str().to_string()),
                    );
                }
            }
            all_reports.push(r);
        }
    }

    match args.common.format.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&all_reports)?;
            println!("{json}");
        }
        _ => render_text(&all_reports, args.common.quiet),
    }

    Ok(0)
}

fn classify_cli_spec(raw: &str) -> (Ecosystem, String) {
    let trimmed = raw.trim().to_string();
    if trimmed.contains("==") {
        (Ecosystem::Pypi, trimmed)
    } else {
        (Ecosystem::Npm, trimmed)
    }
}

fn render_text(reports: &[Value], quiet: bool) {
    for report in reports {
        let target = report
            .get("target")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>");
        let ecosystem = report
            .get("ecosystem")
            .and_then(Value::as_str)
            .unwrap_or("npm");
        let risk = report
            .get("risk")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let score = report.get("score").and_then(Value::as_u64).unwrap_or(0);
        let findings = report
            .get("findings")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);

        println!(
            "[{ecosystem:<4}] {target}  risk={risk}  score={score}  findings={findings}"
        );

        if !quiet {
            if let Some(arr) = report.get("findings").and_then(Value::as_array) {
                for finding in arr.iter().take(6) {
                    let kind = finding.get("kind").and_then(Value::as_str).unwrap_or("?");
                    let detail = finding.get("detail").and_then(Value::as_str).unwrap_or("");
                    let severity = finding
                        .get("severity")
                        .and_then(Value::as_str)
                        .unwrap_or("?");
                    let points = finding.get("points").and_then(Value::as_u64).unwrap_or(0);
                    println!("  [{severity}] {kind} (+{points}): {detail}");
                }
                if arr.len() > 6 {
                    println!("  ... {} more findings", arr.len() - 6);
                }
            }
        }
    }
}
