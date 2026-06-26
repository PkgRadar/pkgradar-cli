use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use serde_json::Value;

pub const DEFAULT_BASE_URL: &str = "https://pkgradar.com";

/// The server rejected the API token (HTTP 401). This is a CONFIGURATION
/// error, not a transient outage — so the gate must NOT fail-open on it.
/// Silently passing a build whose token is wrong means zero coverage while
/// the step shows green (the worst failure mode). Carried as a typed error
/// so the gate loop can downcast and hard-fail regardless of `fail_open`.
#[derive(Debug)]
pub struct AuthRejected;

impl std::fmt::Display for AuthRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "authentication failed (401): the server rejected this API token"
        )
    }
}

impl std::error::Error for AuthRejected {}

pub struct Client {
    inner: reqwest::Client,
    base_url: String,
    token: String,
}

#[derive(Debug, Deserialize)]
pub struct GateResponse {
    pub allowed: bool,
    pub fail_on: String,
    #[serde(default)]
    pub blocked: Vec<BlockedItem>,
    #[serde(default)]
    pub reports: Vec<Value>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BlockedItem {
    pub target: String,
    pub risk: String,
    #[serde(default)]
    pub score: Option<u32>,
    #[serde(default)]
    pub summary: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ScanResponse {
    #[serde(default)]
    pub reports: Vec<Value>,
}

impl Client {
    pub fn new(base_url: String, token: String, timeout_ms: u64) -> Result<Self> {
        // Tokens are routinely pasted into CI secret fields (or `--token`),
        // which commonly append a trailing newline or stray spaces. Left in,
        // that becomes part of the `Authorization: Bearer <token>\n` header
        // value — which reqwest refuses to serialize ("failed to parse header
        // value"). Every request then fails and, under fail-open, the build
        // goes green having scanned NOTHING. Trim before anything else.
        let token = token.trim().to_string();
        if token.is_empty() {
            return Err(anyhow!(
                "no API token. Set PKGRADAR_TOKEN or pass --token. Issue one at \
                 https://pkgradar.com/dashboard/keys.\n  On GitLab, an empty token \
                 here usually means the CI variable is \"Protected\" but this pipeline \
                 ran on a non-protected branch (e.g. a merge request) — un-protect the \
                 variable or protect the branch."
            ));
        }
        // A token carrying bytes illegal in an HTTP header value (controls,
        // embedded whitespace, non-ASCII) is a configuration error, not a
        // transient outage. Fail loudly HERE rather than let every request
        // die at header-build time and fail-open to a false green.
        if token.bytes().any(|b| !(0x21..=0x7e).contains(&b)) {
            return Err(anyhow!(
                "API token contains characters that aren't valid in an HTTP header \
                 (whitespace, control, or non-ASCII bytes). Re-copy the token from \
                 https://pkgradar.com/dashboard/keys — a stray newline or space from \
                 pasting into a CI secret is the usual cause."
            ));
        }
        let inner = reqwest::Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .user_agent(concat!("pkgradar-cli/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("building HTTP client")?;
        Ok(Self {
            inner,
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
        })
    }

    pub async fn gate(
        &self,
        ecosystem: &str,
        specs: &[String],
        fail_on: &str,
        fail_on_cve: Option<&str>,
    ) -> Result<GateResponse> {
        let mut payload = serde_json::json!({
            "specs": specs,
            "fail_on": fail_on,
            "ecosystem": ecosystem,
        });
        // Only send fail_on_cve when set, so older servers that don't know
        // the field aren't handed an unexpected value. Default behaviour
        // (advisories are informational, never block) needs no field.
        if let Some(sev) = fail_on_cve {
            payload["fail_on_cve"] = serde_json::Value::String(sev.to_string());
        }
        // Path includes the ecosystem so server logs + access logs are
        // legible without parsing the body. The body's `ecosystem`
        // field is the canonical source on the server side; the path
        // is informational.
        let url = format!("{}/gate/{ecosystem}", self.base_url);
        let response = self
            .inner
            .post(&url)
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .header(CONTENT_TYPE, "application/json")
            .json(&payload)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;

        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(anyhow::Error::new(AuthRejected));
        }
        if !(status.is_success() || status == reqwest::StatusCode::UNPROCESSABLE_ENTITY) {
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("unexpected response {status}: {body}"));
        }
        let body: GateResponse = response
            .json()
            .await
            .with_context(|| format!("parsing /gate/{ecosystem} response"))?;
        Ok(body)
    }

    #[cfg(test)]
    pub fn token_for_test(&self) -> &str {
        &self.token
    }

    pub async fn scan(&self, ecosystem: &str, specs: &[String]) -> Result<ScanResponse> {
        let payload = serde_json::json!({ "specs": specs });
        let url = format!("{}/scan/{ecosystem}", self.base_url);
        let response = self
            .inner
            .post(&url)
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .header(CONTENT_TYPE, "application/json")
            .json(&payload)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(anyhow::Error::new(AuthRejected));
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("unexpected response {status}: {body}"));
        }
        let body: ScanResponse = response
            .json()
            .await
            .with_context(|| format!("parsing /scan/{ecosystem} response"))?;
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_with_trailing_newline_is_trimmed() {
        // The exact bug: a token pasted into a CI secret with a trailing
        // newline must be cleaned, not break header construction.
        let c = Client::new("https://x".into(), "  pkr_abc123\n".into(), 1000).unwrap();
        assert_eq!(c.token_for_test(), "pkr_abc123");
    }

    #[test]
    fn whitespace_only_token_is_rejected() {
        assert!(Client::new("https://x".into(), "\n   \t".into(), 1000).is_err());
    }

    #[test]
    fn structurally_invalid_token_is_rejected_not_failed_open() {
        // Internal space and non-ASCII can't go in a header — must error at
        // construction (hard fail), never reach the fail-open path.
        assert!(Client::new("https://x".into(), "pkr_ab cd".into(), 1000).is_err());
        assert!(Client::new("https://x".into(), "pkr_\u{00e9}".into(), 1000).is_err());
    }
}
