//! Waiver matching: name glob, semver range, expiry — pure, fully unit-tested.

use semver::{Version, VersionReq};
use std::time::{SystemTime, UNIX_EPOCH};

/// Days since the Unix epoch (1970-01-01 = 0) for a proleptic-Gregorian date.
/// Howard Hinnant's `days_from_civil`.
#[allow(dead_code)] // wired into gate.rs in a later task
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400; // [0, 399]
    let m = m as i64;
    let d = d as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// Parse `YYYY-MM-DD` with range-checked month (1-12) and day (1-31). Returns
/// None on any malformed input.
#[allow(dead_code)] // wired into gate.rs in a later task
pub fn parse_ymd(s: &str) -> Option<(i64, u32, u32)> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let y: i64 = parts[0].parse().ok()?;
    let m: u32 = parts[1].parse().ok()?;
    let d: u32 = parts[2].parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some((y, m, d))
}

/// Today as days-since-epoch (UTC). Clock-before-epoch degrades to day 0.
#[allow(dead_code)] // wired into gate.rs in a later task
pub fn today_days() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86_400) as i64)
        .unwrap_or(0)
}

/// A waiver is expired iff its expiry day is strictly before today (valid
/// through the expiry date itself).
#[allow(dead_code)] // wired into gate.rs in a later task
pub fn is_expired(expires_day: i64, today: i64) -> bool {
    expires_day < today
}

/// Glob match with `*` wildcard (no `?`). No `*` = exact match. Segments split
/// on `*` must appear in order; first is an anchored prefix, last an anchored
/// suffix. Package names are ASCII so byte slicing is safe.
#[allow(dead_code)] // wired into gate.rs in a later task
pub fn name_glob_matches(pattern: &str, name: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == name;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut rest = name;
    if let Some(first) = parts.first() {
        if !rest.starts_with(first) {
            return false;
        }
        rest = &rest[first.len()..];
    }
    if let Some(last) = parts.last() {
        if !rest.ends_with(last) {
            return false;
        }
        rest = &rest[..rest.len() - last.len()];
    }
    let middle = if parts.len() > 2 {
        &parts[1..parts.len() - 1]
    } else {
        &[][..]
    };
    for mid in middle {
        if mid.is_empty() {
            continue;
        }
        match rest.find(mid) {
            Some(pos) => rest = &rest[pos + mid.len()..],
            None => return false,
        }
    }
    true
}

/// True iff `version` parses as semver AND satisfies `req`. An unparseable
/// version returns false — we never waive what we can't range-check.
#[allow(dead_code)] // wired into gate.rs in a later task
pub fn version_matches(req: &VersionReq, version: &str) -> bool {
    Version::parse(version)
        .map(|v| req.matches(&v))
        .unwrap_or(false)
}

/// Split a gate target into (name, version). PyPI uses `name==version`; every
/// other ecosystem uses `name@version` (the last `@`, so npm scopes survive).
#[allow(dead_code)] // wired into gate.rs in a later task
pub fn split_target(target: &str) -> (&str, &str) {
    if let Some((n, v)) = target.split_once("==") {
        (n, v)
    } else if let Some((n, v)) = target.rsplit_once('@') {
        (n, v)
    } else {
        (target, "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_glob() {
        assert!(name_glob_matches("sharp", "sharp"));
        assert!(!name_glob_matches("sharp", "sharpie"));
        assert!(name_glob_matches("sharp*", "sharp-darwin-arm64"));
        assert!(name_glob_matches("*-darwin-*", "sharp-darwin-arm64"));
        assert!(name_glob_matches("@scope/*", "@scope/pkg"));
        assert!(name_glob_matches("*", "anything"));
        assert!(name_glob_matches("a*c", "abc"));
        assert!(!name_glob_matches("a*c", "abd"));
        assert!(!name_glob_matches("a*a", "a")); // needs >= "aa"
    }

    #[test]
    fn version_match() {
        use semver::VersionReq;
        let req = VersionReq::parse(">=0.33.0, <0.34.0").unwrap();
        assert!(version_matches(&req, "0.33.5"));
        assert!(!version_matches(&req, "0.34.0"));
        assert!(!version_matches(&req, "0.32.9"));
        let caret = VersionReq::parse("^0.33").unwrap();
        assert!(version_matches(&caret, "0.33.9"));
        assert!(!version_matches(&caret, "0.34.0"));
        let r2 = VersionReq::parse(">=0.10.0").unwrap();
        assert!(!version_matches(&r2, "0.9.0"));
        assert!(version_matches(&r2, "0.10.0"));
        assert!(!version_matches(&req, "not-a-version"));
    }

    #[test]
    fn split_target_parses_name_and_version() {
        assert_eq!(split_target("sharp@0.33.5"), ("sharp", "0.33.5"));
        assert_eq!(split_target("@scope/pkg@1.2.3"), ("@scope/pkg", "1.2.3"));
        assert_eq!(split_target("flask==2.0.0"), ("flask", "2.0.0"));
        assert_eq!(
            split_target("group:artifact@1.0"),
            ("group:artifact", "1.0")
        );
        assert_eq!(split_target("noversion"), ("noversion", ""));
    }

    #[test]
    fn civil_days_known_points() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1970, 1, 2), 1);
        assert_eq!(days_from_civil(2000, 1, 1), 10957);
        assert_eq!(
            days_from_civil(2024, 3, 1) - days_from_civil(2024, 2, 29),
            1
        );
    }

    #[test]
    fn parse_ymd_ok_and_junk() {
        assert_eq!(parse_ymd("2026-09-01"), Some((2026, 9, 1)));
        assert!(parse_ymd("2026-13-01").is_none());
        assert!(parse_ymd("2026-09-32").is_none());
        assert!(parse_ymd("nope").is_none());
        assert!(parse_ymd("2026/09/01").is_none());
    }

    #[test]
    fn expired_boundary() {
        let today = days_from_civil(2026, 6, 26);
        assert!(is_expired(days_from_civil(2026, 6, 25), today));
        assert!(!is_expired(days_from_civil(2026, 6, 26), today));
        assert!(!is_expired(days_from_civil(2026, 6, 27), today));
    }
}
