use anyhow::Result;
use clap::Args;
use serde_json::Value;
use std::path::PathBuf;

use crate::client::Client;
use crate::cmd::CommonArgs;
use crate::lockfile;

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// One or more npm package specs, e.g. `@scope/name@1.2.3`. Optional
    /// when `--lockfile` is provided.
    #[arg(num_args = 0..)]
    pub specs: Vec<String>,

    /// Path to a lockfile to scan (npm / pnpm / yarn-classic).
    #[arg(long)]
    pub lockfile: Option<PathBuf>,

    #[command(flatten)]
    pub common: CommonArgs,
}

pub async fn run(args: ScanArgs) -> Result<i32> {
    let mut specs: Vec<String> = args.specs.clone();
    if let Some(path) = &args.lockfile {
        let entries = lockfile::parse(path)?;
        for entry in entries {
            specs.push(entry.spec());
        }
    }
    if specs.is_empty() {
        return Err(anyhow::anyhow!(
            "no specs provided. Pass --lockfile <path> or one or more `name@version` args."
        ));
    }
    let client = Client::new(
        args.common.base_url,
        args.common.token,
        args.common.timeout_ms,
    )?;
    let response = client.scan(&specs).await?;

    match args.common.format.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&response.reports)?;
            println!("{json}");
        }
        _ => render_text(&response.reports, args.common.quiet),
    }

    Ok(0)
}

fn render_text(reports: &[Value], quiet: bool) {
    for report in reports {
        let target = report
            .get("target")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>");
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
            "{target}  risk={risk}  score={score}  findings={findings}",
        );

        if !quiet {
            if let Some(arr) = report.get("findings").and_then(Value::as_array) {
                for finding in arr.iter().take(6) {
                    let kind = finding.get("kind").and_then(Value::as_str).unwrap_or("?");
                    let detail = finding
                        .get("detail")
                        .and_then(Value::as_str)
                        .unwrap_or("");
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
