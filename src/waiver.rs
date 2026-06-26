//! Waiver matching: name glob, semver range, expiry — pure, fully unit-tested.

use semver::{Version, VersionReq};
use std::time::{SystemTime, UNIX_EPOCH};

/// Days since the Unix epoch (1970-01-01 = 0) for a proleptic-Gregorian date.
/// Howard Hinnant's `days_from_civil`.
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
pub fn parse_ymd(s: &str) -> Option<(i64, u32, u32)> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let y: i64 = parts[0].parse().ok()?;
    let m: u32 = parts[1].parse().ok()?;
    let d: u32 = parts[2].parse().ok()?;
    if !(1..=12).contains(&m) {
        return None;
    }
    // Reject phantom calendar dates (e.g. 2026-02-31). days_from_civil's modular
    // arithmetic would silently map them to a later real date, making a waiver
    // outlive its intended expiry.
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let max_day = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if !(1..=max_day).contains(&d) {
        return None;
    }
    Some((y, m, d))
}

/// Today as days-since-epoch (UTC). Clock-before-epoch degrades to day 0.
pub fn today_days() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86_400) as i64)
        .unwrap_or(0)
}

/// A waiver is expired iff its expiry day is strictly before today (valid
/// through the expiry date itself).
pub fn is_expired(expires_day: i64, today: i64) -> bool {
    expires_day < today
}

/// Glob match with `*` wildcard (no `?`). No `*` = exact match. Segments split
/// on `*` must appear in order; first is an anchored prefix, last an anchored
/// suffix. Package names are ASCII so byte slicing is safe.
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
pub fn version_matches(req: &VersionReq, version: &str) -> bool {
    Version::parse(version)
        .map(|v| req.matches(&v))
        .unwrap_or(false)
}

/// Split a gate target into (name, version). PyPI uses `name==version`; every
/// other ecosystem uses `name@version` (the last `@`, so npm scopes survive).
pub fn split_target(target: &str) -> (&str, &str) {
    if let Some((n, v)) = target.split_once("==") {
        (n, v)
    } else if let Some((n, v)) = target.rsplit_once('@') {
        (n, v)
    } else {
        (target, "")
    }
}

use crate::config::Waiver;

/// A validated waiver: version req pre-compiled, expiry pre-parsed to a day
/// number. Built once at gate startup; matching is then allocation-light.
#[derive(Debug, Clone)]
pub struct CompiledWaiver {
    pub package: String,
    pub req: Option<VersionReq>,
    pub reason: String,
    pub reviewer: Option<String>,
    pub expires_day: Option<i64>,
    pub expires_str: Option<String>,
}

impl CompiledWaiver {
    /// Validate + compile. Err(message) on: empty package/reason, invalid semver
    /// requirement, or unparseable `expires`.
    pub fn compile(w: &Waiver) -> Result<CompiledWaiver, String> {
        if w.package.trim().is_empty() {
            return Err("waiver `package` is empty".to_string());
        }
        if w.reason.trim().is_empty() {
            return Err(format!(
                "waiver for \"{}\" has an empty `reason`",
                w.package
            ));
        }
        let req = match &w.versions {
            Some(s) => Some(
                VersionReq::parse(s)
                    .map_err(|e| format!("waiver for \"{}\": bad `versions` ({e})", w.package))?,
            ),
            None => None,
        };
        let expires_day = match &w.expires {
            Some(s) => {
                let (y, m, d) = parse_ymd(s).ok_or_else(|| {
                    format!("waiver for \"{}\": `expires` must be YYYY-MM-DD", w.package)
                })?;
                Some(days_from_civil(y, m, d))
            }
            None => None,
        };
        Ok(CompiledWaiver {
            package: w.package.clone(),
            req,
            reason: w.reason.clone(),
            reviewer: w.reviewer.clone(),
            expires_day,
            expires_str: w.expires.clone(),
        })
    }
}

/// What happened when matching one blocked item against the waiver set.
#[derive(Debug, PartialEq, Eq)]
pub enum WaiverOutcome {
    Applied(usize),
    Expired(usize),
    NoMatch,
}

/// Decide a single (name, version). First non-expired match wins; if the only
/// matches are expired, report the first expired one so the caller can warn.
pub fn decide(name: &str, version: &str, waivers: &[CompiledWaiver], today: i64) -> WaiverOutcome {
    let mut first_expired: Option<usize> = None;
    for (i, w) in waivers.iter().enumerate() {
        if !name_glob_matches(&w.package, name) {
            continue;
        }
        let version_ok = match &w.req {
            Some(req) => version_matches(req, version),
            None => true,
        };
        if !version_ok {
            continue;
        }
        match w.expires_day {
            Some(e) if is_expired(e, today) => {
                if first_expired.is_none() {
                    first_expired = Some(i);
                }
            }
            _ => return WaiverOutcome::Applied(i),
        }
    }
    match first_expired {
        Some(i) => WaiverOutcome::Expired(i),
        None => WaiverOutcome::NoMatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cw(pkg: &str, ver: Option<&str>, expires: Option<&str>) -> CompiledWaiver {
        CompiledWaiver::compile(&crate::config::Waiver {
            package: pkg.to_string(),
            versions: ver.map(String::from),
            reason: "r".to_string(),
            reviewer: None,
            expires: expires.map(String::from),
        })
        .unwrap()
    }

    #[test]
    fn compile_rejects_bad_input() {
        use crate::config::Waiver;
        let bad_pkg = Waiver {
            package: "".into(),
            reason: "r".into(),
            ..Default::default()
        };
        assert!(CompiledWaiver::compile(&bad_pkg).is_err());
        let bad_reason = Waiver {
            package: "x".into(),
            reason: "".into(),
            ..Default::default()
        };
        assert!(CompiledWaiver::compile(&bad_reason).is_err());
        let bad_ver = Waiver {
            package: "x".into(),
            reason: "r".into(),
            versions: Some("not-a-req!!".into()),
            ..Default::default()
        };
        assert!(CompiledWaiver::compile(&bad_ver).is_err());
        let bad_date = Waiver {
            package: "x".into(),
            reason: "r".into(),
            expires: Some("2026-99-99".into()),
            ..Default::default()
        };
        assert!(CompiledWaiver::compile(&bad_date).is_err());
    }

    #[test]
    fn decide_outcomes() {
        let today = days_from_civil(2026, 6, 26);
        let ws = vec![
            cw("sharp", Some(">=0.33.0, <0.34.0"), Some("2026-12-31")),
            cw("left-pad", None, None),
            cw("oldwaiver", None, Some("2026-01-01")),
        ];
        assert!(matches!(
            decide("sharp", "0.33.5", &ws, today),
            WaiverOutcome::Applied(0)
        ));
        assert!(matches!(
            decide("sharp", "0.34.0", &ws, today),
            WaiverOutcome::NoMatch
        ));
        assert!(matches!(
            decide("left-pad", "9.9.9", &ws, today),
            WaiverOutcome::Applied(1)
        ));
        assert!(matches!(
            decide("oldwaiver", "1.0.0", &ws, today),
            WaiverOutcome::Expired(2)
        ));
        assert!(matches!(
            decide("unrelated", "1.0.0", &ws, today),
            WaiverOutcome::NoMatch
        ));
        // Expired waiver listed BEFORE a valid one for the same package: the
        // valid match must win (Applied), not the earlier expired one.
        let ordered = vec![
            cw("dup", None, Some("2026-01-01")), // expired, index 0
            cw("dup", None, Some("2026-12-31")), // valid, index 1
        ];
        assert!(matches!(
            decide("dup", "1.0.0", &ordered, today),
            WaiverOutcome::Applied(1)
        ));
    }

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
        // Phantom calendar dates must be rejected (not silently mapped forward).
        assert!(parse_ymd("2026-02-31").is_none());
        assert!(parse_ymd("2026-04-31").is_none());
        assert!(parse_ymd("2026-02-29").is_none()); // 2026 not a leap year
        assert_eq!(parse_ymd("2024-02-29"), Some((2024, 2, 29))); // leap year OK
    }

    #[test]
    fn expired_boundary() {
        let today = days_from_civil(2026, 6, 26);
        assert!(is_expired(days_from_civil(2026, 6, 25), today));
        assert!(!is_expired(days_from_civil(2026, 6, 26), today));
        assert!(!is_expired(days_from_civil(2026, 6, 27), today));
    }
}
