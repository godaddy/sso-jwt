# sso-jwt Design Document

## Overview

`sso-jwt` obtains JWTs through the OAuth 2.0 Device Authorization Grant
(RFC 8628) and caches them encrypted with hardware-backed keys. Tokens are
encrypted at rest using the platform's strongest available mechanism (Secure
Enclave, TPM 2.0, or software keys with keyring encryption).

---

## Workspace Layout

| Crate | Type | Purpose |
|---|---|---|
| `sso-jwt` | Binary | CLI: default get-JWT, `exec`, `shell-init`, `install`, `uninstall`, `add-server` |
| `sso-jwt-lib` | Library | Config loading, OAuth device code flow, JWT parsing, binary cache format, token lifecycle |
| `sso-jwt-napi` | cdylib | Node.js native addon via napi-rs |
| `sso-jwt-tpm-bridge` | Binary | Windows TPM 2.0 bridge for WSL (JSON-RPC over stdin/stdout) |

External dependency: the `libenclaveapp` workspace at `../crates/` provides
`enclaveapp-core`, `enclaveapp-apple`, `enclaveapp-windows`, `enclaveapp-bridge`,
`enclaveapp-software`, `enclaveapp-wsl`, and `enclaveapp-app-storage`.

---

## Configuration Model

### Precedence (lowest to highest)

1. On-disk TOML config file
2. `SSOJWT_*` environment variables
3. CLI flags / programmatic overrides

### Config File

Path: `~/.config/sso-jwt/config.toml` (XDG on Linux/macOS, `APPDATA` on Windows).

```toml
default_server = "myco"
risk_level = 2
biometric = false
cache_name = "default"

[servers.myco]
client_id = "myco-oauth-client"

[servers.myco.environments.prod]
default = true
oauth_url = "https://auth.myco.com/device/code"
token_url = "https://auth.myco.com/token"
heartbeat_url = "https://auth.myco.com/heartbeat"
```

Structs:
- `FileConfig`: `default_server`, `risk_level`, `biometric`, `cache_name`, `servers` map
- `ServerFileConfig`: `client_id`, `environments` map
- `EnvironmentFileConfig`: `default`, `oauth_url`, `token_url`, `heartbeat_url`

### Environment Variables

| Variable | Overrides |
|---|---|
| `SSOJWT_SERVER` | Server profile name |
| `SSOJWT_ENVIRONMENT` | Environment within server profile |
| `SSOJWT_OAUTH_URL` | Device authorization endpoint |
| `SSOJWT_TOKEN_URL` | Token polling endpoint |
| `SSOJWT_HEARTBEAT_URL` | Heartbeat refresh endpoint |
| `SSOJWT_CLIENT_ID` | OAuth client ID |
| `SSOJWT_RISK_LEVEL` | Risk level (1-3) |
| `SSOJWT_BIOMETRIC` | `"true"` or `"1"` to enable |
| `SSOJWT_CACHE_NAME` | Cache file namespace |

### Server Resolution

`Config::resolve_server()` looks up the named server profile, finds the
default or named environment, and populates `oauth_url`, `token_url`,
`heartbeat_url`, and `client_id`. Resolution is skipped when `oauth_url` is
already non-empty ("direct URL mode"). All endpoint URLs are validated for
HTTPS before use.

`Config::load_for_clear()` provides best-effort loading for cache clearing --
malformed config files do not prevent clearing caches.

---

## Cache Binary Format

Cache files use a fixed binary format with an unencrypted header so that token
lifecycle state can be checked without decrypting (avoiding an unnecessary
hardware key access for expired tokens).

```
Offset  Size  Field
------  ----  -----
0       4     Magic bytes: "SJWT" (0x534A5754)
4       1     Format version: 0x01
5       1     Risk level at write time (1-3)
6       8     token_iat: big-endian u64, Unix seconds
14      8     session_start: big-endian u64, Unix seconds
22      4     ciphertext_len: big-endian u32
26      N     Ciphertext (N = ciphertext_len bytes, encrypted JWT)
```

Total header size: 26 bytes. Ciphertext is the JWT encrypted via the platform's
`EncryptionStorage` implementation.

---

## Cache File Naming

### Primary Format (current)

```
server={encoded_server}--env={encoded_env}--cache={encoded_cache}.enc
```

The `env` component is omitted when the environment is `None`:

```
server={encoded_server}--cache={encoded_cache}.enc
```

### Encoding

Alphanumeric characters, `-`, and `_` pass through unchanged. All other bytes
are encoded as `~XX` (uppercase hex). Empty values are replaced with
`"default"`. This scheme prevents both path traversal and aliasing.

### Legacy Format (migration only)

```
{server}-{env}-{cache}.enc
```

Legacy paths are consulted for read on cache lookup when all components are
"legacy-safe" (no hyphens, no path traversal characters). On a successful read
from a legacy path, the token is re-encrypted and written to the primary path,
then the legacy file is removed. Components containing hyphens are treated as
ambiguous (e.g., `a-b-c` could be server=`a-b`/cache=`c` or server=`a`/env=`b`/cache=`c`)
and are not migrated.

### Lookup and Clear Paths

- `cache_lookup_paths()`: primary path first, then legacy path (if safe)
- `cache_clear_paths()`: both primary and legacy paths
- `purge_deprecated_legacy_cache_files()`: removes all `.enc` files in the
  cache directory that do not start with `server=`

Cache directory: `~/.config/sso-jwt/` (same as config directory).

---

## Token Lifecycle

### States

| State | Meaning |
|---|---|
| `Fresh` | Token is well within its validity window. Return cached token directly. |
| `RefreshWindow` | Token is approaching expiration. Try heartbeat refresh; fall back to cached token. |
| `Grace` | Token has just expired. Try heartbeat refresh; fall back to full re-auth. |
| `Dead` | Token is fully expired or session timeout exceeded. Full re-auth required. |

### Classification

Given `token_age = now - token_iat` and `session_age = now - session_start`:

1. If `session_age >= session_timeout` --> `Dead`
2. If `token_age < max_age - refresh_window` --> `Fresh`
3. If `token_age < max_age` --> `RefreshWindow`
4. If `token_age < max_age + 300s` --> `Grace`
5. Otherwise --> `Dead`

### Timing Table

| Risk Level | Max Age | Refresh Window | Grace Period | Session Timeout |
|---|---|---|---|---|
| 1 (low) | 24h (86400s) | last 2h (7200s) | 5min (300s) | 72h (259200s) |
| 2 (medium) | 12h (43200s) | last 1h (3600s) | 5min (300s) | 24h (86400s) |
| 3 (high) | 1h (3600s) | last 10min (600s) | 5min (300s) | 8h (28800s) |

### Effective Risk Level

`effective_risk = max(cached_risk_level, configured_risk_level)`

This prevents a config change from weakening the policy on an existing cached
token. Invalid risk levels (0, >3) are normalized to 2 (medium).

---

## Token Resolution Flow

`cache::resolve_token(config, storage)` is wrapped by `ResolveLock`, an
exclusive `fs4` `flock` on a sibling `<cache>.lock` file. Concurrent `sso-jwt
get` invocations for the same server/environment queue behind the lock so only
one Device Code prompt surfaces at a time. See THREAT_MODEL.md T20.

1. Find the first existing cache file from `cache_lookup_paths()` (primary,
   then legacy).
2. Read the 26-byte header (no decryption).
3. Compute effective risk level and classify token state.
4. Action by state:
   - **Fresh**: Decrypt and return. Migrate legacy cache path if needed.
   - **RefreshWindow**: Decrypt. If `heartbeat_url` is configured, attempt
     heartbeat refresh. On success, write new cache to primary path and return
     refreshed token. On failure, warn and return cached token. If no
     heartbeat URL, return cached token directly.
   - **Grace**: If `heartbeat_url` is configured, decrypt and attempt refresh.
     On success, write new cache and return. On failure, fall through to
     re-auth. If no heartbeat URL, fall through immediately.
   - **Dead**: Fall through to re-auth.
5. Full re-authentication: call `oauth::authenticate()`.
6. Write new cache with `session_start = token_iat`.
7. Clean up legacy cache file if a new write went to the primary path.

---

## OAuth Device Code Flow

### Device Authorization Request

`oauth::get_device_code()`: POST to `oauth_url`

```
Content-Type: application/x-www-form-urlencoded
Accept: application/json

client_id={url_encoded_client_id}
```

Parameters are form-encoded via `reqwest::form()` (not hand-built strings).

Response:
```json
{
  "device_code": "...",
  "user_code": "ABCD1234",
  "verification_uri": "https://...",
  "interval": 5,
  "expires_in": 600
}
```

### User Interaction

- User code formatted as `XXXX-XXXX` (chunks of 4, uppercased, dash-separated).
  Codes longer than 8 characters produce additional groups (e.g., `ABCD-EFGH-IJ`).
- Browser opened via `open::that()`. Falls back to `$BROWSER` env var (parsed
  via `shell_words` to support `BROWSER="firefox --private-window"`).

### Token Polling

`oauth::poll_for_token()`: POST to `token_url` (or `oauth_url` if no separate
token URL is configured)

```
Content-Type: application/x-www-form-urlencoded
Accept: application/json

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code
&client_id={url_encoded_client_id}
&device_code={url_encoded_device_code}
```

Poll responses:
- `authorization_pending`: continue polling at `interval`
- `slow_down`: double the poll interval
- `access_token` present: return the token
- Any other error: fail

### Heartbeat Refresh

`oauth::heartbeat_refresh()`: POST to `heartbeat_url`

```
Authorization: sso-jwt {existing_token}
```

Expects HTTP 201 with `{"data": "new-jwt-value"}`. Returns `None` on any
failure (non-201 status, network error, missing data field).

---

## JWT Parsing

`jwt::parse_claims()` extracts `iat`, `exp`, and `sub` from the JWT payload.
No signature verification -- that is the SSO server's responsibility. The JWT
is split on `.`, the middle segment (payload) is base64-decoded using a
fallback chain:

1. base64url without padding (standard JWT encoding)
2. base64url with padding
3. standard base64 with padding
4. standard base64 without padding

---

## CLI Commands

| Command | Description |
|---|---|
| *(default)* | Print JWT to stdout |
| `exec --env-var NAME -- CMD ARGS...` | Run child process with JWT in the specified env var (default: `SSO_JWT`). JWT is injected only into the child's environment. |
| `shell-init [bash\|zsh\|fish\|auto]` | Print shell integration script for export detection |
| `install` | Platform-specific setup (shell profile on Unix, WSL distro installation on Windows) |
| `uninstall` | Reverse of install |
| `add-server [LABEL] --from-url URL \| --from-github owner/repo@ref/path [--force]` | Add server profile from a TOML source |
| `--clear` | Delete cached tokens and exit |

### add-server

Fetches server config TOML from a remote source. Two fetch strategies:

1. **raw.githubusercontent.com**: Direct HTTPS fetch using the pinned ref
2. **`gh api`**: GitHub CLI with `GH_PROMPT_DISABLED=1`, `stdin(null)`,
   and timeout enforcement

The `gh` binary is *not* resolved via `$PATH`. `gh_discovery::find_trusted_gh`
searches a fixed allowlist of package-manager install dirs
(`/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin`, `~/.local/bin`,
`~/.cargo/bin` on Unix; `%LOCALAPPDATA%\Programs\gh\bin` and
`%ProgramFiles%\GitHub CLI` on Windows), plus the current executable's own
directory. Each candidate is `canonicalize()`d and verified to be an
executable regular file before being used. If no trusted `gh` is found, the
helper returns `Ok(None)` and the caller falls through to the raw-URL HTTPS
fetch. See THREAT_MODEL.md T19.

Constraints:
- GitHub source requires a pinned ref (`owner/repo@ref/path`), no HEAD resolution
- Cleartext HTTP URLs are rejected
- Response body capped at 64 KB
- HTTP timeout: 30 seconds
- `gh` CLI timeout: 30 seconds (enforced via reader thread + `mpsc::recv_timeout`)

---

## TPM Bridge Protocol

`sso-jwt-tpm-bridge` is a Windows-only binary. Its `main.rs` is a thin wrapper
that delegates to `enclaveapp_tpm_bridge::BridgeServer` in libenclaveapp. The
full JSON-RPC protocol — methods (`init`/`encrypt`/`decrypt`/`destroy`/`delete`),
request/response shape, `access_policy` handling, and `ensure_key()` policy
enforcement — lives in that upstream crate. See
[`crates/enclaveapp-tpm-bridge`](https://github.com/godaddy/libenclaveapp/tree/main/crates/enclaveapp-tpm-bridge)
for the canonical spec.

Policy metadata is stored in a `.meta` sidecar file alongside the key. When
the sidecar is present and matches the requested `AccessPolicy`, the existing
key is reused; when absent or mismatched, the key is deleted and regenerated.

---

## Node.js Binding

Single export: `getJwt(options?: JwtOptions): Promise<string>`

### JwtOptions Interface

```typescript
interface JwtOptions {
  server?: string;
  env?: string;
  oauthUrl?: string;
  tokenUrl?: string;
  heartbeatUrl?: string;
  clientId?: string;
  cacheName?: string;
  riskLevel?: number;   // 1-3, validated at binding layer
  biometric?: boolean;
  noOpen?: boolean;
}
```

Implementation runs `sso_jwt_lib::get_jwt()` on a `tokio::task::spawn_blocking`
thread. Risk level is validated at the NAPI boundary (rejects values outside
1-3 before the Rust `u32 -> u8` cast).

---

## Platform Backend Selection

| Platform | Backend | Provider Crate |
|---|---|---|
| macOS | Secure Enclave (CryptoKit) | `enclaveapp-apple` |
| Windows | TPM 2.0 (CNG/NCrypt) | `enclaveapp-windows` |
| WSL | Windows TPM via bridge binary | `enclaveapp-wsl` + `sso-jwt-tpm-bridge` |
| Linux with TPM | TPM 2.0 (tss-esapi) | `enclaveapp-core` |
| Linux without TPM | Software keys + D-Bus Secret Service keyring | `enclaveapp-software` |

Storage is initialized via `enclaveapp_app_storage::create_encryption_storage()`
with:

```rust
StorageConfig {
    app_name: "sso-jwt",
    key_label: "cache-key",
    access_policy: AccessPolicy::BiometricOnly | AccessPolicy::None,
    extra_bridge_paths: vec![],
    keys_dir: None,
}
```

---

## Security Properties

- **Encryption at rest**: All cached tokens are encrypted using hardware-backed
  keys. Plaintext tokens never touch disk.
- **HTTPS-only endpoints**: All `oauth_url`, `token_url`, and `heartbeat_url`
  values are validated to use HTTPS. Cleartext HTTP is rejected at config load.
- **File permissions**: Cache and config files are restricted to owner-only
  permissions on Unix via `metadata::restrict_file_permissions`.
- **Atomic writes**: Cache and config files are written atomically via
  `metadata::atomic_write` to prevent partial/corrupt reads.
- **Exec mode**: JWT is injected only into the child process environment, not
  the parent shell. `shell-init` warns on `export SSO_JWT=...` patterns.
- **Cache path encoding**: Path components are `~XX`-encoded, preventing both
  path traversal and aliasing attacks.
- **Pinned GitHub refs**: `add-server --from-github` requires a pinned ref
  (commit SHA or tag). No HEAD/branch resolution.
- **Fetch limits**: Remote server config responses are capped at 64 KB with a
  30-second HTTP timeout.
- **No signature verification**: JWTs are not signature-verified locally. This
  is the SSO server's responsibility. The local tool only cares about `iat`
  for lifecycle management.
- **Key policy enforcement**: The TPM bridge validates that existing keys match
  the requested `AccessPolicy` and regenerates on mismatch or missing metadata.

---

## Build Requirements

- Rust stable (pinned via `rust-toolchain.toml`, edition 2021)
- macOS: Xcode (for swiftc via libenclaveapp)
- Linux: `libdbus-1-dev`, `pkg-config`
- Windows: Visual Studio Build Tools

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```
