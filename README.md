# sso-jwt

Rust toolkit for obtaining SSO JWTs with hardware-backed secure caching.

`sso-jwt` replaces the older Node.js `ssojwt` workflow with a native implementation that:

- caches tokens encrypted at rest
- supports Secure Enclave, TPM, WSL bridge, and software fallback backends
- uses server-profile configuration instead of hardcoded single-endpoint assumptions
- supports both CLI and Node.js consumers

## Workspace

| Crate | Purpose |
|---|---|
| [`sso-jwt`](sso-jwt/) | CLI binary |
| [`sso-jwt-lib`](sso-jwt-lib/) | core token, config, cache, and OAuth logic |
| [`sso-jwt-napi`](sso-jwt-napi/) | Node.js native addon |
| [`sso-jwt-tpm-bridge`](sso-jwt-tpm-bridge/) | Windows TPM bridge for WSL |

## Installation

**[Download latest release](https://github.com/godaddy/sso-jwt/releases/latest)** for macOS, Windows, and Linux.

### Homebrew

```bash
brew tap godaddy/sso-jwt
brew install sso-jwt
```

### Scoop

```powershell
scoop bucket add sso-jwt https://github.com/godaddy/scoop-sso-jwt
scoop install sso-jwt
```

### From source

```bash
cargo install --path sso-jwt
```

## Quick start

```bash
# safest common path
sso-jwt exec -- terraform apply

# or capture stdout for a single child process
SSO_JWT=$(sso-jwt) terraform apply

# install shell guardrails
eval "$(sso-jwt shell-init zsh)"
```

The default `exec` variable name is `SSO_JWT`. Shell integration also warns on common `COMPANY_JWT` export patterns because that was used in earlier workflows.

## CLI surface

```text
sso-jwt [OPTIONS] [COMMAND]

Commands:
  shell-init   Print shell integration script
  exec         Run a command with the JWT injected into its environment
  install      Print install guidance or configure WSL from Windows
  uninstall    Remove WSL config on Windows or print manual removal guidance
  add-server   Add a server profile from a URL, GitHub repo, or local file
```

Key options:

- `--server`
- `--environment`
- `--cache-name`
- `--risk-level`
- `--oauth-url`
- `--biometric`
- `--no-open`
- `--clear`

## Configuration

Configuration lives at `~/.config/sso-jwt/config.toml`.

Current config shape:

```toml
default_server = "myco"
risk_level = 2
biometric = false
cache_name = "default"

[servers.myco]
client_id = "sso-jwt"

[servers.myco.environments.prod]
default = true
oauth_url = "https://sso.example.com/oauth/device"
token_url = "https://sso.example.com/oauth/token"
heartbeat_url = "https://sso.example.com/oauth/heartbeat"
```

Environment variable overrides:

| Variable | Purpose |
|---|---|
| `SSOJWT_SERVER` | server profile name |
| `SSOJWT_ENVIRONMENT` | environment within the selected server |
| `SSOJWT_OAUTH_URL` | direct OAuth device URL override |
| `SSOJWT_TOKEN_URL` | token polling URL override |
| `SSOJWT_HEARTBEAT_URL` | heartbeat URL override |
| `SSOJWT_CLIENT_ID` | client ID override |
| `SSOJWT_RISK_LEVEL` | risk level override |
| `SSOJWT_BIOMETRIC` | biometric override |
| `SSOJWT_CACHE_NAME` | cache-name override |

`sso-jwt exec` uses `--env-var` to choose the child-process environment variable name. That setting is not part of the persisted config file.

## Server profiles

You can add a server from a local file, URL, or GitHub repo path:

```bash
sso-jwt add-server myco --from-url ./server.toml
sso-jwt add-server github --from-github owner/repo/path/to/server.toml
```

If you omit the label, `add-server` stores the profile as `default` and also sets it as `default_server`.

## Platform security

All platform-specific crypto comes from [libenclaveapp](https://github.com/godaddy/libenclaveapp).

| Platform | Backend |
|---|---|
| macOS | Secure Enclave |
| Windows | TPM 2.0 |
| WSL | Windows TPM bridge |
| Linux with TPM | TPM 2.0 |
| Linux without TPM | software fallback |

## Development

```bash
cargo build
cargo test
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Node addon build:

```bash
cd sso-jwt-napi
npm install
npm run build
```

## License

MIT
