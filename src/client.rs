use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use serde_json::Value;

pub const DEFAULT_BASE_URL: &str = "https://pkgradar.com";

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
        if token.is_empty() {
            return Err(anyhow!(
                "no API token. Set PKGRADAR_TOKEN or pass --token. Issue one at https://pkgradar.com/dashboard/keys."
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
    ) -> Result<GateResponse> {
        let payload = serde_json::json!({
            "specs": specs,
            "fail_on": fail_on,
            "ecosystem": ecosystem,
        });
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
            return Err(anyhow!(
                "authentication failed (401). Check PKGRADAR_TOKEN."
            ));
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
            return Err(anyhow!(
                "authentication failed (401). Check PKGRADAR_TOKEN."
            ));
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
