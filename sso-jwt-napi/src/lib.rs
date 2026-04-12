use napi_derive::napi;

/// Options for obtaining a JWT.
/// Matches the Node.js `getJwt()` parameter shape.
#[napi(object)]
#[derive(Debug, Default)]
pub struct JwtOptions {
    /// Server profile name
    pub server: Option<String>,
    /// Environment within the server profile
    pub env: Option<String>,
    /// Override OAuth service URL
    pub oauth_url: Option<String>,
    /// Override heartbeat URL
    pub heartbeat_url: Option<String>,
    /// Override client ID
    pub client_id: Option<String>,
    /// Cache name for the encrypted token
    pub cache_name: Option<String>,
    /// Risk level 1-3 (1=low/24h, 2=medium/12h, 3=high/1h)
    pub risk_level: Option<u32>,
    /// Require biometric (Touch ID / Windows Hello) for each use
    pub biometric: Option<bool>,
    /// Don't auto-open browser
    pub no_open: Option<bool>,
    /// Environment variable name override
    pub env_var: Option<String>,
}

/// Obtain a JWT via the OAuth Device Code flow with hardware-backed caching.
///
/// Returns a cached token if one exists and is still valid.
/// Proactively refreshes tokens approaching expiration via heartbeat.
/// Falls back to full browser-based re-authentication when necessary.
///
/// ```javascript
/// const { getJwt } = require('sso-jwt');
/// const jwt = await getJwt({ server: 'myserver' });
/// ```
#[napi]
pub async fn get_jwt(options: Option<JwtOptions>) -> napi::Result<String> {
    let opts = convert_options(options);

    tokio::task::spawn_blocking(move || sso_jwt_lib::get_jwt(&opts))
        .await
        .map_err(|e| napi::Error::from_reason(format!("task join error: {e}")))?
        .map_err(|e| napi::Error::from_reason(format!("{e:#}")))
}

/// Backward-compatible alias for `getJwt`. Drop-in replacement for
/// `sso-jwt-legacy`'s `getJwt()`.
#[napi]
pub async fn get_jwt(options: Option<JwtOptions>) -> napi::Result<String> {
    get_jwt(options).await
}

fn convert_options(options: Option<JwtOptions>) -> sso_jwt_lib::GetJwtOptions {
    match options {
        None => sso_jwt_lib::GetJwtOptions::default(),
        Some(o) => sso_jwt_lib::GetJwtOptions {
            server: o.server,
            env: o.env,
            oauth_url: o.oauth_url,
            heartbeat_url: o.heartbeat_url,
            client_id: o.client_id,
            cache_name: o.cache_name,
            risk_level: o.risk_level.map(|v| v as u8),
            biometric: o.biometric,
            no_open: o.no_open,
            env_var: o.env_var,
        },
    }
}
