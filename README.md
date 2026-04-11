# sso-jwt

A Rust CLI for obtaining SSO JWTs with hardware-backed secure caching.

Replaces the Node.js `ssojwt` tool with a fast, single-binary alternative that encrypts cached tokens using the Secure Enclave (macOS), TPM 2.0 (Windows), or a software keyring (Linux). Tokens never touch disk as plaintext and are never exported into long-lived shell environment variables.

## Installation

### From source

```bash
cargo install --path sso-jwt
```

### Homebrew (planned)

```bash
brew install sso-jwt
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

Subsequent runs return the cached token instantly (no browser, no network) until it approaches expiration, at which point it's proactively refreshed via the SSO heartbeat endpoint.

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

Add to your shell profile to get best-effort detection of accidental `export` usage:

```bash
# ~/.zshrc
eval "$(sso-jwt shell-init zsh)"

# ~/.bashrc
eval "$(sso-jwt shell-init bash)"

# ~/.config/fish/config.fish
sso-jwt shell-init fish | source
```

When installed, attempting `export COMPANY_JWT=$(sso-jwt)` will produce an error:

```
error: refusing to output JWT for 'export'. This would persist the token in your shell environment.
       Use: COMPANY_JWT=$(sso-jwt) your-command
       Or:  sso-jwt exec -- your-command
```

This is a best-effort guardrail using shell-specific hooks (zsh `preexec`, bash `DEBUG` trap). It catches common interactive misuse but is not bulletproof against indirect invocations or scripts.

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

The absolute session timeout prevents indefinite refresh chains. After the session timeout, a full browser-based re-authentication is required regardless of the current token's age.

## Platform Security

### macOS (Secure Enclave)

Requires T2 chip (2018+ Intel Macs) or Apple Silicon. The encryption key is a P-256 EC key pair generated inside the Secure Enclave. Encryption uses ECIES (cofactor X9.63 SHA-256 AES-GCM). The private key never leaves the hardware.

With `--biometric`, Touch ID is required for every cache read. Without it, the key is accessible whenever the device is unlocked.

### Windows (TPM 2.0)

Requires TPM 2.0 module. The encryption key is created via the Microsoft Platform Crypto Provider (CNG). Key material is hardware-resident and non-exportable.

With `--biometric`, Windows Hello is required via `NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG`.

### WSL

WSL is auto-detected. A bridge process (`sso-jwt-tpm-bridge.exe`) on the Windows host performs TPM operations. The Linux binary communicates with it via JSON-RPC over stdin/stdout pipes.

Requires `sso-jwt` to be installed on the Windows host first.

### Linux

Uses the D-Bus Secret Service API (GNOME Keyring / KDE Wallet). This is software-only -- no hardware binding -- but still encrypts the cache with the user's login keyring.

## Cache Format

Cached tokens are stored at `$XDG_CONFIG_HOME/sso-jwt/<cache-name>.enc` as a binary file:

| Bytes | Field |
|---|---|
| 0-3 | Magic: `SJWT` |
| 4 | Format version (0x01) |
| 5 | Risk level |
| 6-13 | Token issued-at (u64 BE) |
| 14-21 | Session start (u64 BE) |
| 22-25 | Ciphertext length (u32 BE) |
| 26-N | ECIES ciphertext blob |

The header is readable without decryption, allowing expiration checks without touching the Secure Enclave / TPM.

## Compatibility

The new CLI talks to the same webservice as the existing Node.js `ssojwt` tool. No server-side changes are needed. The OAuth Device Code flow, client ID, and API endpoints are identical.

The existing plaintext cache at `~/.cache/sso-jwt/` is not read or migrated. First run with the new tool requires a fresh authentication.

## Development

```bash
# Build
cargo build

# Run tests
cargo test

# Lint
cargo clippy

# Release build
cargo build --release
```

### Project Structure

```
sso-jwt-rs/
  sso-jwt/                     Main CLI binary
    src/
      main.rs                  Entry point
      cli.rs                   Clap CLI definition and dispatch
      config.rs                Config file + env var loading
      oauth.rs                 OAuth Device Code flow
      cache.rs                 Cache format, token lifecycle, proactive refresh
      jwt.rs                   JWT parsing (base64 decode, iat extraction)
      shell_init.rs            Shell integration script generation
      exec.rs                  Fork/exec with JWT env injection
      secure_storage/
        mod.rs                 SecureStorage trait + platform dispatch
        macos.rs               Secure Enclave via Security.framework
        windows.rs             TPM 2.0 via CNG
        wsl.rs                 WSL TPM bridge client
        linux.rs               D-Bus secret service keyring
    tests/
      integration.rs           CLI integration tests
  sso-jwt-tpm-bridge/          Windows-only TPM bridge binary
    src/
      main.rs                  JSON-RPC server over stdin/stdout
      tpm.rs                   TPM 2.0 operations via CNG
```

## License

MIT
