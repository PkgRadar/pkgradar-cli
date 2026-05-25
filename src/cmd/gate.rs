use anyhow::Result;
use clap::Args;
use serde_json::Value;

use crate::client::{BlockedItem, Client, GateResponse};
use crate::cmd::CommonArgs;

#[derive(Args, Debug)]
pub struct GateArgs {
    /// One or more npm package specs, e.g. `lodash@4.17.21`.
    #[arg(required = true, num_args = 1..)]
    pub specs: Vec<String>,

    /// Block when a spec's risk is at or above this level.
    #[arg(long, default_value = "high", value_parser = ["high", "review", "low"])]
    pub fail_on: String,

    #[command(flatten)]
    pub common: CommonArgs,
}

pub async fn run(args: GateArgs) -> Result<i32> {
    let client = Client::new(
        args.common.base_url,
        args.common.token,
        args.common.timeout_ms,
    )?;
    let response = client.gate(&args.specs, &args.fail_on).await?;

    match args.common.format.as_str() {
        "json" => println!("{}", serde_json::to_string_pretty(&render_json(&response))?),
        _ => render_text(&response, args.common.quiet),
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

fn render_text(response: &GateResponse, quiet: bool) {
    let blocked_specs: std::collections::HashSet<&str> =
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
            "pkgradar: {n} specs passed.",
            n = response.reports.len(),
        );
    }
}
