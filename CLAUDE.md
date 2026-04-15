# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`sso-jwt` obtains SSO JWTs via the OAuth 2.0 Device Authorization Grant (RFC 8628) with hardware-backed secure caching. Tokens are encrypted at rest using the Secure Enclave (macOS), TPM 2.0 (Windows), or software keys with keyring encryption (Linux).

## Integration Type

sso-jwt is a **credential source** that can serve Type 1 or Type 2 enclave apps. It provides JWTs via its CLI (`sso-jwt get`) or NAPI bindings, which other tools consume for authentication. When used as a standalone CLI, it caches encrypted JWTs using hardware-backed storage.

## Build & Development

Rust workspace. Requires Rust 1.82+. macOS builds need Xcode (for swiftc via libenclaveapp). Linux builds need `libdbus-1-dev pkg-config`.

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Architecture

Rust workspace with 4 crates:

- **sso-jwt-lib** -- Core library. OAuth device code flow (RFC 8628), JWT parsing, token lifecycle (Fresh/RefreshWindow/Grace/Dead), binary cache format, heartbeat refresh, config management. Uses `enclaveapp-app-storage` for platform-detected hardware-backed encrypt/decrypt.
- **sso-jwt** -- CLI binary. Commands: (default) get JWT, exec, shell-init, install, uninstall, add-server.
- **sso-jwt-napi** -- Node.js native addon wrapping sso-jwt-lib.
- **sso-jwt-tpm-bridge** -- Windows TPM bridge for WSL (JSON-RPC over stdin/stdout).

### Key Flow

1. Check cache: Fresh -> return immediately. RefreshWindow -> try heartbeat. Dead -> full OAuth flow.
2. OAuth Device Code: POST to `oauth_url` -> get `user_code` + `verification_uri` -> open browser -> poll `token_url` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`
3. Encrypt JWT with hardware key -> write binary cache -> return JWT

### Token Lifecycle (by risk level)

| Risk | Max Age | Refresh Window | Session Timeout |
|------|---------|----------------|-----------------|
| 1    | 24h     | last 2h        | 72h             |
| 2    | 12h     | last 1h        | 24h             |
| 3    | 1h      | last 10min     | 8h              |

### Dependencies

Uses `libenclaveapp` (path dependency at `../libenclaveapp/`) for all hardware-backed cryptography. The `enclaveapp-wsl` crate provides WSL shell integration and shell-init generation.

### Config

Server profiles configured in `~/.config/sso-jwt/config.toml`:
```toml
[servers.github]
client_id = "your-oauth-app-client-id"

[servers.github.environments.prod]
default = true
oauth_url = "https://github.com/login/device/code"
token_url = "https://github.com/login/oauth/access_token"
```

## Platform

- macOS: Secure Enclave via CryptoKit (libenclaveapp)
- Windows: TPM 2.0 via CNG (libenclaveapp)
- WSL: JSON-RPC bridge to Windows TPM
- Linux: Software keys with D-Bus Secret Service keyring encryption, or TPM 2.0 via tss-esapi

## Commits

Do not add Co-Authored-By lines for Claude Code in commit messages.
