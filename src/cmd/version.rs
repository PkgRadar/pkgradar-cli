use anyhow::Result;

pub fn run() -> Result<i32> {
    let default = crate::client::DEFAULT_BASE_URL;
    let configured = std::env::var("PKGRADAR_BASE_URL").unwrap_or_else(|_| default.to_string());
    println!("pkgradar {}", env!("CARGO_PKG_VERSION"));
    println!("api: {configured}");
    Ok(0)
}
