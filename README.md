# pkgradar-cli

PkgRadar's CI gate and static package scanner as a single binary, plus the
GitHub Actions composite that wraps it.

```sh
pkgradar gate --lockfile package-lock.json --fail-on high
```

This repo is the entire installable surface area for the gate. Fork, vendor,
audit, or run it as-is — there's no closed-source path to the binary you run.

## Install

### Prebuilt binaries

Each release tag (`v0.1.0`+) attaches binaries for:

- `pkgradar-x86_64-unknown-linux-gnu.tar.gz`
- `pkgradar-aarch64-unknown-linux-gnu.tar.gz`
- `pkgradar-x86_64-apple-darwin.tar.gz`
- `pkgradar-aarch64-apple-darwin.tar.gz`

```sh
TAG=$(curl -sSfL https://api.github.com/repos/PkgRadar/pkgradar-cli/releases/latest \
  | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name": "([^"]+)".*/\1/')
ARCH=$(uname -m); OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS-$ARCH" in
  linux-x86_64)   ASSET="pkgradar-x86_64-unknown-linux-gnu.tar.gz" ;;
  linux-aarch64)  ASSET="pkgradar-aarch64-unknown-linux-gnu.tar.gz" ;;
  darwin-x86_64)  ASSET="pkgradar-x86_64-apple-darwin.tar.gz" ;;
  darwin-arm64)   ASSET="pkgradar-aarch64-apple-darwin.tar.gz" ;;
esac
curl -sSfL "https://github.com/PkgRadar/pkgradar-cli/releases/download/${TAG}/${ASSET}" \
  | tar -xz
sudo install -m 0755 pkgradar /usr/local/bin/
```

### From crates.io

```sh
cargo install pkgradar --locked
```

### From source

```sh
git clone https://github.com/PkgRadar/pkgradar-cli
cd pkgradar-cli
cargo install --path . --locked
```

## GitHub Actions

The composite action lives at the root of this repo, so you can use it
directly without specifying a subpath:

```yaml
- uses: PkgRadar/pkgradar-cli@v1
  with:
    token: ${{ secrets.PKGRADAR_TOKEN }}
    fail-on: high
    # lockfile: pnpm-lock.yaml   # optional override; auto-detects otherwise
```

| Input       | Required | Default | Meaning                                                                                                       |
|-------------|----------|---------|---------------------------------------------------------------------------------------------------------------|
| `token`     | yes      | —       | API token from <https://pkgradar.com/dashboard/keys>                                                          |
| `lockfile`  | no       | auto    | Path to a lockfile. Auto-detects npm/pnpm/yarn-classic, pip/pipenv/poetry/uv/pdm in the working dir.          |
| `fail-on`   | no       | `high`  | Block on this risk level or worse (`low`, `review`, `high`)                                                   |
| `config`    | no       | —       | Path to a `.pkgradar.yml` config file                                                                         |
| `fail-open` | no       | `true`  | Exit 0 on transport-level API errors (timeout, 5xx). Set `false` to harden.                                   |
| `version`   | no       | latest  | Pin a specific `pkgradar` CLI version, e.g. `v0.1.0`                                                          |
| `base-url`  | no       | —       | Override `https://pkgradar.com` (self-hosted only)                                                            |

The action prefers a prebuilt binary from this repo's releases for fast
cold-start (~10s) and falls back to `cargo install` when the runner platform
isn't in the release matrix.

## GitLab CI

A ready-made template is hosted on pkgradar.com:

```yaml
include:
  - remote: 'https://pkgradar.com/templates/pkgradar.gitlab-ci.yml'

pkgradar-gate:
  extends: .pkgradar-base
  stage: test
  variables:
    PKGRADAR_FAIL_ON: high
```

`PKGRADAR_TOKEN` must be set in Settings → CI/CD → Variables.

> **Heads-up — "Protect variable" is ON by default.** A protected GitLab variable
> is only exposed on protected branches/tags, so a merge-request pipeline from an
> ordinary feature branch sees an *empty* token and the gate fails with
> "PKGRADAR_TOKEN is not set". When adding the variable, **un-check "Protect
> variable"** (or protect the branches you run MRs from). This is the most common
> first-run snag.

## Configure

```sh
export PKGRADAR_TOKEN="rps_..."
export PKGRADAR_BASE_URL="https://pkgradar.com"   # optional
```

Or commit a `.pkgradar.yml` at the root of your repo:

```yaml
fail_on: high
timeout_ms: 30000
fail_open: true
allowlist:
  - "@types/node@22.5.4"   # reviewed and approved internally
watchlist:
  - "react@18.3.1"
```

CLI flags override the config file on conflict.

## Commands

### `pkgradar gate`

Asks the gate endpoint whether each spec should be blocked. Exits non-zero
when any spec breaches `--fail-on`. Combine with `--lockfile` to batch every
transitive in one call.

```sh
pkgradar gate lodash@4.17.21 left-pad@1.3.0 --fail-on high
pkgradar gate --lockfile pnpm-lock.yaml --fail-on review
```

#### Merge-request (diff) mode

By default `pkgradar gate` evaluates the **whole** lockfile, so a pre-existing
high-risk dependency fails every pipeline. On merge requests, pass `--baseline
<git-ref>` to gate only the dependencies the change **adds or version-bumps**:

```sh
pkgradar gate --baseline "$CI_MERGE_REQUEST_DIFF_BASE_SHA"    # GitLab
pkgradar gate --baseline "$(git merge-base origin/main HEAD)" # generic
```

It diffs the current lockfile(s) against the ref (`git show <ref>:<lockfile>`)
and gates only the new `name@version` specs. A pre-existing flagged dep no longer
blocks an unrelated MR; the same dep newly added still does. Requires git on PATH
and the ref fetched (CI shallow-clones — use `fetch-depth: 0` or a `git fetch` of
the target). If the ref can't be resolved, the gate falls back to the full
lockfile with a warning (never less safe). The GitHub Action and GitLab template
wire this automatically on PR/MR pipelines — no flag needed.

### `pkgradar scan`

Returns the full scan report rather than the gate decision. Use this when
you want to see *why* a release would be blocked.

```sh
pkgradar scan @scope/name@1.2.3 --format json | jq '.[0].findings'
pkgradar scan --lockfile yarn.lock --format json
```

### `pkgradar version`

Prints the binary version and the resolved API endpoint.

## Lockfile support

### npm ecosystem

| Format                  | Supported               |
|-------------------------|-------------------------|
| `package-lock.json` v1  | Yes                     |
| `package-lock.json` v2  | Yes                     |
| `package-lock.json` v3  | Yes                     |
| `npm-shrinkwrap.json`   | Yes                     |
| `pnpm-lock.yaml` v6+    | Yes                     |
| `yarn.lock` v1          | Yes                     |
| `yarn.lock` v2+ (Berry) | No — errors with a hint |

### PyPI ecosystem

| Format                        | Supported                                            |
|-------------------------------|------------------------------------------------------|
| `requirements.txt`            | Yes — only fully-pinned (`==`) entries are gated     |
| `requirements.lock` (pip-tools) | Yes                                                |
| `constraints.txt`             | Yes                                                  |
| `Pipfile.lock`                | Yes (default + develop sections)                     |
| `poetry.lock`                 | Yes                                                  |
| `uv.lock`                     | Yes                                                  |
| `pdm.lock`                    | Yes                                                  |

### RubyGems ecosystem

| Format          | Supported                                                                       |
|-----------------|---------------------------------------------------------------------------------|
| `Gemfile.lock`  | Yes (GEM block, registry-resolved pins; GIT/PATH/PLUGIN sources skipped)        |
| `gems.locked`   | Yes                                                                             |

### Cargo (Rust / crates.io) ecosystem

| Format        | Supported                                                                |
|---------------|--------------------------------------------------------------------------|
| `Cargo.lock`  | Yes (registry+ and sparse+ sources; git+ and workspace crates skipped)  |

### Maven (Java / Maven Central) ecosystem

| Format     | Supported                                                                                  |
|------------|--------------------------------------------------------------------------------------------|
| `pom.xml`  | Yes — `<dependency>` blocks with concrete pinned versions; `${prop}` / `[1,2)` ranges skipped, `<dependencyManagement>` ignored |

Maven specs use the `groupId:artifactId@version` shape, e.g.
`com.fasterxml.jackson.core:jackson-databind@2.17.0`.

### NuGet (.NET / nuget.org) ecosystem

| Format                  | Supported                                                            |
|-------------------------|----------------------------------------------------------------------|
| `packages.lock.json`    | Yes (PackageReference lockfile; `type: Project` entries skipped)     |
| `packages.config`       | Yes (legacy XML format)                                              |
| `project.assets.json`   | Yes (resolved restore graph; `type: project` entries skipped)        |

NuGet specs use `Id@Version`, e.g. `Newtonsoft.Json@13.0.3`. IDs are
case-insensitive on the registry.

### Composer (PHP / Packagist) ecosystem

| Format          | Supported                                                                                |
|-----------------|------------------------------------------------------------------------------------------|
| `composer.lock` | Yes (`packages` + `packages-dev` arrays; `metapackage` and `dev-*` refs skipped)         |

Composer specs use `vendor/name@version`, e.g. `symfony/console@v6.4.1`.

The parser deduplicates by `(ecosystem, name, version)`, normalizes
PyPI names per PEP 503, and skips non-registry refs (`file:`, `link:`,
`workspace:`, `git+`, `github:`, direct URL specs).

## Fail-open behaviour

Network or transport-level errors (timeout, 5xx, DNS) print a warning and
exit 0 by default — security tooling shouldn't take down a deploy pipeline
because PkgRadar had a 30-second blip. Set `fail_open: false` in
`.pkgradar.yml` (or pass `--no-fail-open`) once your gate cadence is stable.

## Exit codes

| Code | Meaning                                          |
|------|--------------------------------------------------|
| `0`  | All specs passed the gate.                       |
| `1`  | At least one spec was blocked.                   |
| `2`  | Usage / config error (missing token, bad flag).  |
| `3`  | Network, TLS, or installer failure.              |

## Building locally

```sh
cargo build --release
./target/release/pkgradar --help
cargo test --release
```

The binary is statically linked against `rustls-tls-native-roots`, so it
picks up the host's CA bundle and doesn't link OpenSSL at runtime.

## License

Apache-2.0. See [LICENSE](LICENSE).
