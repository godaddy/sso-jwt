# sso-jwt-lib

Core library for the sso-jwt toolkit. Provides JWT caching with hardware-backed encryption, OAuth Device Code flow, and proactive token refresh.

This crate is used by both the [`sso-jwt`](../sso-jwt/) CLI and the [`sso-jwt-napi`](../sso-jwt-napi/) Node.js binding.

## Usage as a Rust dependency

```toml
[dependencies]
sso-jwt-lib = { path = "../sso-jwt-lib" }
```

### High-level API

```rust
use sso_jwt_lib::{get_jwt, GetJwtOptions};

let options = GetJwtOptions {
    env: Some("prod".to_string()),
    cache_name: Some("my-app".to_string()),
    ..Default::default()
};

let jwt = get_jwt(&options)?;
```

`get_jwt()` handles the full flow: load config, initialize platform secure storage, check the cache, refresh if needed, and fall back to OAuth Device Code authentication.

### Module-level API

For finer control, use the individual modules directly:

```rust
use sso_jwt_lib::{config::Config, cache, secure_storage};

let config = Config::load()?;
let storage = secure_storage::platform_storage(config.biometric)?;
let jwt = cache::resolve_token(&config, storage.as_ref())?;
```

## Modules

| Module | Description |
|---|---|
| `config` | Configuration loading (TOML file + `SSOJWT_*` env vars) |
| `cache` | Binary cache format, token lifecycle (Fresh/Refresh/Grace/Dead), proactive heartbeat refresh |
| `jwt` | JWT parsing: base64url decode, claim extraction (`iat`, `exp`, `sub`) |
| `oauth` | OAuth 2.0 Device Code flow, browser opening with `$BROWSER` fallback, heartbeat refresh |
| `secure_storage` | `SecureStorage` trait with platform backends: Secure Enclave (macOS), TPM 2.0 (Windows), WSL bridge, software keyring (Linux) |

## Platform Backends

The `secure_storage::platform_storage()` function auto-selects the backend:

| Platform | Backend | Hardware-bound |
|---|---|---|
| macOS | Secure Enclave (ECIES P-256) | Yes |
| Windows | TPM 2.0 (CNG) | Yes |
| WSL | TPM bridge to Windows host | Yes |
| Linux | D-Bus Secret Service (GNOME Keyring / KDE Wallet) | No |

## License

MIT
