# sso-jwt

A Rust toolkit for obtaining SSO JWTs with hardware-backed secure caching.

Replaces the Node.js `ssojwt` tool with a fast, native alternative that encrypts cached tokens using the Secure Enclave (macOS), TPM 2.0 (Windows), or a software keyring (Linux). Tokens never touch disk as plaintext and are never exported into long-lived shell environment variables.

## Workspace

This repository is a Cargo workspace containing four crates:

| Crate | Type | Description |
|---|---|---|
| [`sso-jwt`](sso-jwt/) | Binary | CLI tool for obtaining JWTs |
| [`sso-jwt-lib`](sso-jwt-lib/) | Library | Core logic: caching, OAuth, secure storage, JWT parsing |
| [`sso-jwt-napi`](sso-jwt-napi/) | cdylib | Node.js native addon via napi-rs (drop-in replacement for `sso-jwt-legacy`) |
| [`sso-jwt-tpm-bridge`](sso-jwt-tpm-bridge/) | Binary | Windows TPM bridge for WSL environments |

## Installation

### Homebrew (macOS)

```bash
brew tap jgowdy/sso-jwt
brew install sso-jwt
```

### From source

```bash
cargo install --path sso-jwt
```

### Node.js native addon

```bash
cd sso-jwt-napi
npm install
npm run build
```

## Quick Start

```bash
# Authenticate and use the JWT for a single command (recommended)
COMPANY_JWT=$(sso-jwt) terraform apply

# Or use exec mode (most secure -- JWT never touches stdout)
sso-jwt exec -- terraform apply

# Set up shell integration to detect accidental `export` usage
# Add to your .zshrc or .bashrc:
eval "$(sso-jwt shell-init)"
```

On first run, `sso-jwt` will:
1. Generate a hardware-bound encryption key in the Secure Enclave (macOS) or TPM (Windows).
2. Open your browser for Okta authentication via the OAuth Device Code flow.
3. Encrypt and cache the resulting JWT.

Subsequent runs return the cached token instantly until it approaches expiration, at which point it's proactively refreshed via the SSO heartbeat endpoint.

## Usage

```
sso-jwt [OPTIONS] [COMMAND]

Commands:
  shell-init    Print shell integration for export detection (bash/zsh/fish)
  exec          Run a command with the JWT injected into its environment

Options:
  -e, --environment <ENV>     SSO environment [default: prod] [values: dev, test, ote, prod]
  -c, --cache-name <NAME>     Cache name [default: default]
  -r, --risk-level <LEVEL>    Token risk level (1=low/24h, 2=medium/12h, 3=high/1h) [default: 2]
      --oauth-url <URL>       Override OAuth service URL
      --biometric             Require Touch ID / Windows Hello for each use
      --no-open               Don't auto-open browser
      --clear                 Clear cached token and exit
  -h, --help                  Print help
  -V, --version               Print version
```

### Common Patterns

```bash
# Inline variable for a single command (JWT scoped to child process only)
COMPANY_JWT=$(sso-jwt) terraform apply

# Exec mode (JWT never written to stdout)
sso-jwt exec -- kubectl get pods

# Use a specific environment
COMPANY_JWT=$(sso-jwt -e dev) curl https://api.dev-example.com

# High-security mode with Touch ID
sso-jwt --biometric --risk-level 3 | pbcopy

# Multiple environments simultaneously
COMPANY_JWT=$(sso-jwt -c prod) terraform apply
COMPANY_JWT=$(sso-jwt -c dev -e dev) terraform plan

# Clear cached token
sso-jwt --clear
```

### Node.js Library Usage

The napi binding is a drop-in replacement for `sso-jwt-legacy`:

```javascript
// Old (Node.js)
const { getJwt } = require('sso-jwt-legacy');

// New (Rust via napi-rs) -- identical API
const { getJwt } = require('sso-jwt');

const jwt = await getJwt({ env: 'prod', cacheName: 'default' });
```

See [`sso-jwt-napi/README.md`](sso-jwt-napi/) for details.

## Configuration

Configuration file at `$XDG_CONFIG_HOME/sso-jwt/config.toml` (default: `~/.config/sso-jwt/config.toml`):

```toml
# SSO environment
environment = "prod"

# Token risk level (1=low/24h, 2=medium/12h, 3=high/1h)
risk_level = 2

# Require biometric for cache decryption
biometric = false

# Default cache name
cache_name = "default"

# Environment variable name for exec mode
env_var = "COMPANY_JWT"
```

**Precedence:** CLI flags > environment variables (`SSOJWT_*`) > config file > defaults.

### Environment Variables

| Variable | Description |
|---|---|
| `SSOJWT_ENVIRONMENT` | SSO environment (dev/test/ote/prod) |
| `SSOJWT_RISK_LEVEL` | Risk level (1/2/3) |
| `SSOJWT_BIOMETRIC` | Enable biometric (true/1) |
| `SSOJWT_CACHE_NAME` | Cache name |
| `SSOJWT_ENV_VAR` | Env var name for exec mode |
| `SSOJWT_OAUTH_URL` | Override OAuth URL |

## Shell Integration

Add to your shell profile for best-effort detection of accidental `export` usage:

```bash
# ~/.zshrc
eval "$(sso-jwt shell-init zsh)"

# ~/.bashrc
eval "$(sso-jwt shell-init bash)"

# ~/.config/fish/config.fish
sso-jwt shell-init fish | source
```

This is a guardrail, not a guarantee -- it catches common interactive misuse but indirect invocations may bypass it.

## Token Lifecycle

Tokens go through four lifecycle states based on age relative to the risk-level window:

```
  0%                    ~80%                  100%        100% + 5min
  |---- FRESH ----------|---- REFRESH --------|-- GRACE --|-- DEAD -->
```

| State | Behavior |
|---|---|
| **Fresh** | Return cached token immediately. No network calls. |
| **Refresh** | Try heartbeat refresh. On failure, return cached token (still valid). |
| **Grace** | Try heartbeat refresh. On failure, full re-auth. |
| **Dead** | Full re-authentication via OAuth Device Code flow. |

### Expiration Windows

| Risk Level | Max Age | Refresh Window | Absolute Session Timeout |
|---|---|---|---|
| 1 (low) | 24 hours | last 2 hours | 72 hours |
| 2 (medium) | 12 hours | last 1 hour | 24 hours |
| 3 (high) | 1 hour | last 10 minutes | 8 hours |

The absolute session timeout prevents indefinite refresh chains.

## Platform Security

### macOS (Secure Enclave)

Requires T2 chip (2018+ Intel Macs) or Apple Silicon. P-256 EC key pair generated inside the Secure Enclave. Encryption uses ECIES (cofactor X9.63 SHA-256 AES-GCM). The private key never leaves the hardware.

### Windows (TPM 2.0)

Requires TPM 2.0 module. Key created via the Microsoft Platform Crypto Provider (CNG). Key material is hardware-resident and non-exportable.

### WSL

Auto-detected. A bridge process (`sso-jwt-tpm-bridge.exe`) on the Windows host performs TPM operations via JSON-RPC over stdin/stdout pipes.

### Linux

Uses the D-Bus Secret Service API (GNOME Keyring / KDE Wallet). Software-only -- no hardware binding.

## Compatibility

Talks to the same webservice as the existing Node.js `ssojwt` tool. No server-side changes needed. The OAuth Device Code flow, client ID, and API endpoints are identical.

## Development

```bash
# Build all crates
cargo build

# Run all tests (155 tests)
cargo test

# Lint (strict rules enforced via workspace lints)
cargo clippy -- -D warnings

# Release build
cargo build --release

# Build Node.js addon
cd sso-jwt-napi && npm install && npm run build
```

### Project Structure

```
sso-jwt-rs/
  sso-jwt-lib/                  Core library (reusable)
    src/
      lib.rs                    Public API: get_jwt(), GetJwtOptions
      jwt.rs                    JWT parsing (base64 decode, iat extraction)
      config.rs                 Config file + env var loading
      cache.rs                  Cache format, token lifecycle, proactive refresh
      oauth.rs                  OAuth Device Code flow + heartbeat refresh
      secure_storage/
        mod.rs                  SecureStorage trait + platform dispatch
        macos.rs                Secure Enclave via Security.framework
        windows.rs              TPM 2.0 via CNG
        wsl.rs                  WSL TPM bridge client
        linux.rs                D-Bus secret service keyring

  sso-jwt/                      CLI binary
    src/
      main.rs                   Entry point
      cli.rs                    Clap CLI definition and dispatch
      shell_init.rs             Shell integration script generation
      exec.rs                   Fork/exec with JWT env injection
    tests/
      integration.rs            CLI integration tests

  sso-jwt-napi/                 Node.js native addon
    src/lib.rs                  napi-rs binding
    index.js                    Native module loader
    index.d.ts                  TypeScript definitions
    package.json                npm package config

  sso-jwt-tpm-bridge/           Windows TPM bridge for WSL
    src/
      main.rs                   JSON-RPC server over stdin/stdout
      tpm.rs                    TPM 2.0 operations via CNG
```

## License

MIT
