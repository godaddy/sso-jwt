# sso-jwt-lib

Core library for `sso-jwt`.

It owns:

- configuration loading and server-profile resolution
- cache format and token lifecycle
- OAuth Device Code flow and heartbeat refresh
- JWT parsing

Encryption storage is provided by `enclaveapp-app-storage` from `libenclaveapp`.

## High-level API

```rust
use sso_jwt_lib::{get_jwt, GetJwtOptions};

let jwt = get_jwt(&GetJwtOptions {
    server: Some("myco".to_string()),
    env: Some("prod".to_string()),
    cache_name: Some("terraform".to_string()),
    ..Default::default()
})?;
```

## Lower-level usage

If you need more control, build config and storage explicitly:

```rust
use enclaveapp_app_storage::{create_encryption_storage, AccessPolicy, StorageConfig};
use sso_jwt_lib::{cache, config::Config};

let mut config = Config::load()?;
config.resolve_server()?;

let storage = create_encryption_storage(StorageConfig {
    app_name: "sso-jwt".into(),
    key_label: "cache-key".into(),
    access_policy: AccessPolicy::None,
    extra_bridge_paths: vec![],
    keys_dir: None,
})?;

let jwt = cache::resolve_token(&config, storage.as_ref())?;
```

## Public modules

| Module | Purpose |
|---|---|
| `config` | config file loading, env overrides, server/environment resolution |
| `cache` | cache format, lifecycle, clear/resolve helpers |
| `jwt` | JWT parsing utilities |
| `oauth` | Device Code flow and token refresh helpers |

## Config model

`Config` merges:

1. `~/.config/sso-jwt/config.toml`
2. `SSOJWT_*` environment variables
3. caller-provided overrides in `GetJwtOptions`

Server profiles are resolved from:

- `default_server`
- `servers.<name>.client_id`
- `servers.<name>.environments.<env>`

## License

MIT
