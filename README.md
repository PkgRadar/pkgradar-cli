# pkgradar

PkgRadar's CI gate and static package scanner, as a single binary.

```sh
pkgradar gate left-pad@1.3.0
# exit 0 on pass, 1 on block, 2 on bad usage, 3 on network/auth error
```

## Why

A small, dependency-light binary that wraps the PkgRadar HTTP API for use in
GitHub Actions, GitLab CI, Jenkins, pre-commit hooks, and local shells. It's
deliberately the same code we expect customers to audit, which is why it lives
in its own folder of the monorepo and is on track to move to its own
repository.

## Install

```sh
# from source
cargo install --path .

# from prebuilt release (coming soon)
curl -fsSL https://pkgradar.com/install.sh | sh
```

## Configure

```sh
export PKGRADAR_TOKEN="rps_..."
# optional, defaults to https://pkgradar.com
export PKGRADAR_BASE_URL="https://pkgradar.com"
```

Tokens are issued at <https://pkgradar.com/dashboard/keys>.

## Commands

### `pkgradar gate <spec>...`

Asks the gate endpoint whether each package version should be blocked.
Exits non-zero when any spec breaches the `--fail-on` threshold.

```sh
pkgradar gate lodash@4.17.21 left-pad@1.3.0 --fail-on high
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--fail-on` | `high` | Block at this severity or worse (`high`, `review`). |
| `--format` | `text` | `text` or `json`. |
| `--base-url` | `https://pkgradar.com` | Override the API endpoint. |
| `--token` | `$PKGRADAR_TOKEN` | API token. Required. |
| `--quiet` | off | Suppress success output. |
| `--timeout-ms` | `8000` | HTTP timeout per request. |

### `pkgradar scan <spec>...`

Returns the full scan report rather than a gate decision. Use this to see the
findings PkgRadar produced for a package version.

```sh
pkgradar scan @scope/name@1.2.3 --format json | jq '.[0].findings'
```

### `pkgradar version`

Prints the binary version and the resolved API endpoint.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | All specs passed the gate. |
| 1 | At least one spec was blocked. |
| 2 | Usage error (missing token, bad spec, bad flag). |
| 3 | Network, TLS, or authentication failure talking to the API. |

## Building from source

```sh
cargo build --release
./target/release/pkgradar --help
```

Linux, macOS, and Windows are supported. The binary is statically linked
against `rustls-tls-native-roots`, so it picks up the host's CA bundle and
does not require OpenSSL at runtime.

## Roadmap

- `pkgradar gate --lockfile package-lock.json` to gate every dep in a lockfile.
- GitHub Actions annotation output for `--format gha`.
- `pkgradar policy` for client-side allow lists alongside the server gate.
- Homebrew tap, Scoop bucket, and a Docker image.

## License

Apache-2.0. See `LICENSE`.
