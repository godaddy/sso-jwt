# sso-jwt Design Document

## Overview

sso-jwt obtains SSO JWTs via the OAuth Device Code flow (RFC 8628) and
caches them encrypted using hardware-backed keys. Tokens never touch disk
as plaintext and are never exported into long-lived shell environment
variables.

## Architecture

4-crate workspace plus shared dependencies from
[libenclaveapp](https://github.com/jgowdy/libenclaveapp):

| Crate | Type | Purpose |
|---|---|---|
| `sso-jwt` | Binary | CLI tool: token retrieval, exec mode, shell integration |
| `sso-jwt-lib` | Library | Core logic: config, cache, OAuth, secure storage, JWT parsing |
| `sso-jwt-napi` | cdylib | Node.js native addon via napi-rs (drop-in replacement) |
| `sso-jwt-tpm-bridge` | Binary | Windows TPM bridge for WSL environments |

### libenclaveapp Dependency

All platform-specific crypto is delegated to libenclaveapp's `encryption`
feature. `sso-jwt-lib/secure_storage` wraps libenclaveapp's
`EnclaveEncryptor` trait into sso-jwt's `SecureStorage` trait.

## OAuth Device Code Flow

sso-jwt implements RFC 8628 (OAuth 2.0 Device Authorization Grant):

```
User                sso-jwt              Authorization Server
  |                   |                          |
  |  sso-jwt          |                          |
  |------------------>|                          |
  |                   | POST device_authorization|
  |                   |------------------------->|
  |                   |   device_code, user_code |
  |                   |<-------------------------|
  |                   |                          |
  |  "Open browser,   |                          |
  |   enter: XXXX"    |                          |
  |<------------------|                          |
  |                   |                          |
  |  (user authorizes in browser)                |
  |                   |                          |
  |                   | POST token (polling)     |
  |                   |------------------------->|
  |                   |   access_token (JWT)     |
  |                   |<-------------------------|
  |                   |                          |
  |   JWT (stdout     | Encrypt + cache          |
  |   or exec env)    |                          |
  |<------------------|                          |
```

The `oauth_url` is the device authorization endpoint. The `token_url` is
the token polling endpoint. When `token_url` is omitted, `oauth_url` is
used for both (backward compatible with single-endpoint services).

## Token Lifecycle

Tokens go through four lifecycle states based on age relative to the
risk-level window:

```
  0%                    ~80%                  100%        100% + 5min
  |---- FRESH ----------|---- REFRESH --------|-- GRACE --|-- DEAD -->
```

| State | Behavior |
|---|---|
| Fresh | Return cached token immediately. No network calls. |
| Refresh | Try heartbeat refresh. On failure, return cached token. |
| Grace | Try heartbeat refresh. On failure, full re-auth. |
| Dead | Full re-authentication via Device Code flow. |

### Expiration Windows

| Risk Level | Max Age | Refresh Window | Session Timeout |
|---|---|---|---|
| 1 (low) | 24 hours | last 2 hours | 72 hours |
| 2 (medium) | 12 hours | last 1 hour | 24 hours |
| 3 (high) | 1 hour | last 10 minutes | 8 hours |

The absolute session timeout (`session_start` timestamp) prevents
indefinite refresh chains.

## Cache Format

Binary cache format with unencrypted header for fast expiration checks
without hardware calls:

```
Offset  Length  Field
0       4       Magic: "SJWT"
4       1       Format version: 0x01
5       1       Risk level
6       8       Token issued-at (Unix epoch, big-endian)
14      8       Session start (Unix epoch, big-endian)
22      4       Ciphertext length (big-endian)
26      var     ECIES ciphertext (enclaveapp format)
```

Cache files are stored at `~/.config/sso-jwt/<cache_name>.enc`.

## Secure Storage

Each platform backend wraps libenclaveapp's `EnclaveEncryptor`:

| Platform | Backend | Notes |
|---|---|---|
| macOS | Secure Enclave | ECIES via enclaveapp-apple |
| Windows | TPM 2.0 | ECIES via enclaveapp-windows |
| WSL | TPM bridge | JSON-RPC to Windows host via enclaveapp-bridge |
| Linux | Software fallback | File-based encryption, one-time warning |

## Multi-Server Configuration

sso-jwt supports multiple SSO servers via the config file:

```toml
default_server = "internal"

[servers.internal]
client_id = "sso-jwt"

[servers.internal.environments.prod]
default = true
oauth_url = "https://sso.example.com/oauth/device"
token_url = "https://sso.example.com/oauth/token"

[servers.github]
client_id = "github-oauth-app-id"

[servers.github.environments.prod]
default = true
oauth_url = "https://github.com/login/device/code"
token_url = "https://github.com/login/oauth/access_token"
```

Each server can have multiple environments (dev, test, prod) with
independent OAuth endpoints. The `--server` and `--environment` CLI flags
select which to use.

## Configuration Precedence

CLI flags > environment variables (`SSOJWT_*`) > config file > defaults.

## Security Design

- Tokens encrypted at rest with hardware-bound ECIES keys
- `exec` mode injects JWT into child process environment only
- Shell integration detects accidental `export` usage
- `Zeroizing<Vec<u8>>` for all in-memory token buffers
- Absolute session timeouts prevent indefinite refresh chains
- File permissions: 0700 dirs, 0600 files

## WSL Bridge

Same architecture as awsenc: JSON-RPC over stdin/stdout to
`sso-jwt-tpm-bridge.exe` on the Windows host. Bridge binary is installed
alongside the main Windows installer.
