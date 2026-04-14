# sso-jwt Design Document

## Overview

`sso-jwt` obtains JWTs through the OAuth Device Code flow and caches them encrypted with hardware-backed keys when available.

The current design has three important properties:

1. token caching is encrypted at rest
2. cache state is namespaced by server, environment, and cache name
3. server configuration is profile-based rather than hardcoded to one endpoint

## Workspace

| Crate | Purpose |
|---|---|
| `sso-jwt` | CLI commands, shell integration, install/uninstall helpers |
| `sso-jwt-lib` | config loading, OAuth flow, cache lifecycle, JWT parsing |
| `sso-jwt-napi` | Node.js binding |
| `sso-jwt-tpm-bridge` | Windows bridge process for WSL |

## Storage design

`sso-jwt-lib` uses `enclaveapp-app-storage` from `libenclaveapp` for encryption storage. That shared layer is responsible for:

- backend selection
- key initialization
- WSL bridge discovery
- access-policy mapping

`sso-jwt` passes:

- `app_name = "sso-jwt"`
- `key_label = "cache-key"`
- `AccessPolicy::BiometricOnly` when `--biometric` is enabled

## Configuration model

The active configuration is built from:

1. config file
2. `SSOJWT_*` environment variables
3. CLI overrides

The config file stores:

- `default_server`
- `risk_level`
- `biometric`
- `cache_name`
- `servers.<name>.client_id`
- `servers.<name>.environments.<env>.oauth_url`
- optional `token_url`
- optional `heartbeat_url`

Direct `--oauth-url` use bypasses server-profile resolution.

## Cache model

Cache files live under `~/.config/sso-jwt/` and are named from:

- server
- environment, when present
- cache name

That keeps multiple concurrent environments and servers isolated from each other.

The cache lifecycle is:

- `Fresh`
- `Refresh`
- `Grace`
- `Dead`

Risk level controls the refresh window and absolute session timeout.

## CLI design

The main CLI supports:

- direct token output
- `exec` mode with child-only environment injection
- shell guardrails through `shell-init`
- `install` and `uninstall`
- `add-server` for onboarding new server profiles

The default `exec` variable name is `SSO_JWT`.

## Platform model

| Platform | Backend |
|---|---|
| macOS | Secure Enclave |
| Windows | TPM 2.0 |
| WSL | Windows TPM bridge |
| Linux with TPM | TPM 2.0 |
| Linux without TPM | software fallback |

## Security boundaries

The main security goal is to avoid plaintext token files. `sso-jwt` does not try to eliminate all token exposure after decryption; that is why `exec` mode exists and is preferred for command execution.
