use anyhow::Result;
use clap::Args;
use serde_json::Value;

use crate::client::Client;
use crate::cmd::CommonArgs;

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// One or more npm package specs, e.g. `@scope/name@1.2.3`.
    #[arg(required = true, num_args = 1..)]
    pub specs: Vec<String>,

    #[command(flatten)]
    pub common: CommonArgs,
}

pub async fn run(args: ScanArgs) -> Result<i32> {
    let client = Client::new(
        args.common.base_url,
        args.common.token,
        args.common.timeout_ms,
    )?;
    let response = client.scan(&args.specs).await?;

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
