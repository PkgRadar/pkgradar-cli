//! Waiver matching: name glob, semver range, expiry — pure, fully unit-tested.

use semver::{Version, VersionReq};

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
}
