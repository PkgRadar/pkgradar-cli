use clap::Subcommand;

pub mod gate;
pub mod scan;
pub mod version;

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Ask the gate endpoint whether a package version should be blocked.
    Gate(gate::GateArgs),
    /// Fetch the full scan report for a package version.
    Scan(scan::ScanArgs),
    /// Print the binary version and resolved API endpoint.
    Version,
}

#[derive(clap::Args, Debug, Clone)]
pub struct CommonArgs {
    /// API token. Get one at https://pkgradar.com/dashboard/keys.
    #[arg(long, env = "PKGRADAR_TOKEN", hide_env_values = true)]
    pub token: String,

    /// API base URL. Override only if you're self-hosting or testing.
    #[arg(
        long,
        env = "PKGRADAR_BASE_URL",
        default_value = crate::client::DEFAULT_BASE_URL
    )]
    pub base_url: String,

    /// HTTP timeout in milliseconds, per request. Default is generous
    /// because a cold gate batch triggers first-time live scans server-side
    /// (fetch + analyze each tarball); repeat runs hit the cache and are fast.
    #[arg(long, default_value_t = 60000)]
    pub timeout_ms: u64,

    /// Output format.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Suppress non-error output.
    #[arg(long)]
    pub quiet: bool,
}
