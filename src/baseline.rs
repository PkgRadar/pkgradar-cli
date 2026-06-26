//! Diff a lockfile against a baseline git ref so the gate can act only on
//! newly-introduced dependencies (MR mode). The pure set-diff lives here and is
//! unit-tested without git; the git plumbing (added by a later task) gets its
//! own integration test.

use std::collections::HashSet;

use crate::lockfile::LockfileEntry;

/// Current entries whose `(ecosystem, name, version)` spec is NOT present in the
/// baseline. Captures added packages and version bumps; skips unchanged entries;
/// ignores removed ones (removing a dep can't introduce risk). Order-preserving.
pub fn new_entries(current: &[LockfileEntry], baseline: &[LockfileEntry]) -> Vec<LockfileEntry> {
    let base: HashSet<String> = baseline.iter().map(|e| e.spec()).collect();
    current
        .iter()
        .filter(|e| !base.contains(&e.spec()))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::{Ecosystem, LockfileEntry};

    fn e(eco: Ecosystem, name: &str, ver: &str) -> LockfileEntry {
        LockfileEntry {
            ecosystem: eco,
            name: name.to_string(),
            version: ver.to_string(),
        }
    }

    #[test]
    fn new_entries_returns_added_and_bumped_only() {
        use Ecosystem::*;
        let baseline = vec![e(Npm, "lodash", "4.17.21"), e(Npm, "left-pad", "1.3.0")];
        let current = vec![
            e(Npm, "lodash", "4.17.21"), // unchanged -> skipped
            e(Npm, "left-pad", "1.3.1"), // bumped -> NEW (new triple)
            e(Npm, "sharp", "0.33.5"),   // added -> NEW
        ];
        let got: Vec<String> = new_entries(&current, &baseline)
            .iter()
            .map(|x| x.spec())
            .collect();
        assert_eq!(
            got,
            vec!["left-pad@1.3.1".to_string(), "sharp@0.33.5".to_string()]
        );
    }

    #[test]
    fn new_entries_empty_baseline_is_all_new() {
        use Ecosystem::*;
        let current = vec![e(Npm, "a", "1.0.0"), e(Pypi, "b", "2.0.0")];
        assert_eq!(new_entries(&current, &[]).len(), 2);
    }

    #[test]
    fn new_entries_removed_pkg_not_returned() {
        use Ecosystem::*;
        let baseline = vec![e(Npm, "gone", "1.0.0"), e(Npm, "keep", "1.0.0")];
        let current = vec![e(Npm, "keep", "1.0.0")]; // removed `gone`, nothing added
        assert!(new_entries(&current, &baseline).is_empty());
    }
}
