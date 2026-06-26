//! Diff a lockfile against a baseline git ref so the gate can act only on
//! newly-introduced dependencies (MR mode). The pure set-diff lives here and is
//! unit-tested without git; the git plumbing (added by a later task) gets its
//! own integration test.
//!
//! Everything here is wired into `gate.rs` by the diff-wiring task; until then
//! the non-test items have no non-test caller.
#![allow(dead_code)] // used by gate.rs in the diff-wiring task

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

use crate::lockfile::{self, LockfileEntry};

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

/// Outcome of fetching a lockfile's baseline content at a ref.
#[derive(Debug)]
pub enum BaselineOutcome {
    /// Parsed baseline entries. EMPTY means the lockfile did not exist at the
    /// ref — so every current entry is "new".
    Entries(Vec<LockfileEntry>),
    /// The path existed at the ref but its content couldn't be fetched/parsed.
    /// The caller treats this as an empty baseline AND warns (gates more = safe).
    Unreadable,
}

/// True if `git_ref` resolves to a commit in the repo containing `cwd`.
pub fn ref_is_resolvable_in(cwd: &Path, git_ref: &str) -> bool {
    Command::new("git")
        .current_dir(cwd)
        .args([
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{git_ref}^{{commit}}"),
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false) // git missing -> not resolvable
}

/// Repo-relative path for `git show <ref>:<path>`. Falls back to the file name
/// if `ls-files` can't place it (untracked/odd path).
fn repo_relative(dir: &Path, basename: &str) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .args(["ls-files", "--full-name", "--", basename])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s.is_empty() {
                basename.to_string()
            } else {
                s
            }
        }
        _ => basename.to_string(),
    }
}

/// Fetch and parse `lockfile` as it existed at `git_ref`.
pub fn baseline_entries(git_ref: &str, lockfile: &Path) -> BaselineOutcome {
    let dir = lockfile
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let basename = match lockfile.file_name().and_then(|n| n.to_str()) {
        Some(b) => b.to_string(),
        None => return BaselineOutcome::Unreadable,
    };
    let relpath = repo_relative(dir, &basename);

    let out = match Command::new("git")
        .current_dir(dir)
        .args(["show", &format!("{git_ref}:{relpath}")])
        .output()
    {
        Ok(o) => o,
        Err(_) => return BaselineOutcome::Unreadable, // git missing (shouldn't happen post ref check)
    };
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        // Path simply absent at the ref -> empty baseline (all current is new).
        if err.contains("does not exist") || err.contains("exists on disk") {
            return BaselineOutcome::Entries(Vec::new());
        }
        return BaselineOutcome::Unreadable;
    }

    // Write to a temp file whose BASENAME matches the original, so
    // lockfile::parse dispatches on the right format.
    let tmp = std::env::temp_dir().join(format!(
        "pkgr_bl_{}_{}",
        std::process::id(),
        sanitize(&relpath)
    ));
    if std::fs::create_dir_all(&tmp).is_err() {
        return BaselineOutcome::Unreadable;
    }
    let tmpfile = tmp.join(&basename);
    if std::fs::write(&tmpfile, &out.stdout).is_err() {
        return BaselineOutcome::Unreadable;
    }
    let parsed = lockfile::parse(&tmpfile);
    let _ = std::fs::remove_dir_all(&tmp);
    match parsed {
        Ok(entries) => BaselineOutcome::Entries(entries),
        Err(_) => BaselineOutcome::Unreadable,
    }
}

/// Make a relpath safe as a single temp dir-name component.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
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

    use std::fs;
    use std::path::PathBuf;
    use std::process::Command as Cmd;

    fn git(dir: &Path, args: &[&str]) {
        let ok = Cmd::new("git")
            .current_dir(dir)
            .args(args)
            .status()
            .unwrap()
            .success();
        assert!(ok, "git {:?} failed", args);
    }

    fn temp_repo() -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pkgr_bl_test_{}_{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        git(&dir, &["init", "-q"]);
        git(&dir, &["config", "user.email", "t@t"]);
        git(&dir, &["config", "user.name", "t"]);
        dir
    }

    #[test]
    fn baseline_entries_reads_lockfile_at_ref() {
        let dir = temp_repo();
        let lf = dir.join("package-lock.json");
        let base =
            r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}"#;
        fs::write(&lf, base).unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-qm", "base"]);

        // Mutate working tree (add a dep) WITHOUT committing.
        let cur = r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"},"node_modules/sharp":{"version":"0.33.5"}}}"#;
        fs::write(&lf, cur).unwrap();

        match baseline_entries("HEAD", &lf) {
            BaselineOutcome::Entries(es) => {
                let specs: Vec<String> = es.iter().map(|e| e.spec()).collect();
                assert!(specs.iter().any(|s| s == "lodash@4.17.21"), "got {specs:?}");
                assert!(
                    !specs.iter().any(|s| s.starts_with("sharp")),
                    "baseline must not see sharp"
                );
            }
            other => panic!("expected Entries, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn baseline_entries_absent_at_ref_is_empty() {
        let dir = temp_repo();
        fs::write(dir.join("README"), "x").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-qm", "base"]);
        let lf = dir.join("package-lock.json");
        fs::write(&lf, r#"{"lockfileVersion":3,"packages":{}}"#).unwrap();
        match baseline_entries("HEAD", &lf) {
            BaselineOutcome::Entries(es) => {
                assert!(es.is_empty(), "absent-at-ref must be empty baseline")
            }
            other => panic!("expected empty Entries, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ref_resolvable_true_false() {
        let dir = temp_repo();
        fs::write(dir.join("README"), "x").unwrap();
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-qm", "base"]);
        assert!(ref_is_resolvable_in(&dir, "HEAD"));
        assert!(!ref_is_resolvable_in(&dir, "definitelynotaref123"));
        let _ = fs::remove_dir_all(&dir);
    }
}
