use napi_derive::napi;

/// Options for obtaining a JWT.
/// Matches the Node.js `getJwt()` parameter shape.
#[napi(object)]
#[derive(Debug, Default)]
pub struct JwtOptions {
    /// SSO environment: "dev", "test", "ote", "prod"
    pub env: Option<String>,
    /// Override OAuth service URL
    pub oauth_url: Option<String>,
    /// Cache name for the encrypted token
    pub cache_name: Option<String>,
    /// Risk level 1-3 (1=low/24h, 2=medium/12h, 3=high/1h)
    pub risk_level: Option<u32>,
    /// Require biometric (Touch ID / Windows Hello) for each use
    pub biometric: Option<bool>,
    /// Don't auto-open browser
    pub no_open: Option<bool>,
}

/// Obtain an SSO JWT, authenticating via the OAuth Device Code flow if needed.
///
/// Returns a cached token if one exists and is still valid.
/// Proactively refreshes tokens approaching expiration via the SSO heartbeat.
/// Falls back to full browser-based re-authentication when necessary.
///
/// This function is the drop-in replacement for the Node.js
/// `sso-jwt-legacy` package's `getJwt()`.
///
/// ```javascript
/// const { getJwt } = require('sso-jwt');
///
/// const jwt = await getJwt({ env: 'prod', cacheName: 'default' });
/// ```
#[napi]
pub async fn get_jwt(
    options: Option<JwtOptions>,
) -> napi::Result<String> {
    let opts = convert_options(options);

    // Run blocking IO (HTTP requests, Secure Enclave/TPM calls) off
    // the Node.js event loop thread.
    tokio::task::spawn_blocking(move || sso_jwt_lib::get_jwt(&opts))
        .await
        .map_err(|e| napi::Error::from_reason(format!("task join error: {e}")))?
        .map_err(|e| napi::Error::from_reason(format!("{e:#}")))
}

fn convert_options(options: Option<JwtOptions>) -> sso_jwt_lib::GetJwtOptions {
    match options {
        None => sso_jwt_lib::GetJwtOptions::default(),
        Some(o) => sso_jwt_lib::GetJwtOptions {
            env: o.env,
            oauth_url: o.oauth_url,
            cache_name: o.cache_name,
            risk_level: o.risk_level.map(|v| v as u8),
            biometric: o.biometric,
            no_open: o.no_open,
        },
    }
}
