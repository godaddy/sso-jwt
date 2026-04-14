use napi_derive::napi;

/// Options for obtaining a JWT.
#[napi(object)]
#[derive(Debug, Default)]
pub struct JwtOptions {
    /// Server profile name
    pub server: Option<String>,
    /// Environment within the server profile
    pub env: Option<String>,
    /// Override OAuth service URL
    pub oauth_url: Option<String>,
    /// Override token polling URL (separate from device authorization endpoint)
    pub token_url: Option<String>,
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
}

/// Obtain a JWT via the OAuth Device Code flow with hardware-backed caching.
///
/// ```javascript
/// const { getJwt } = require('sso-jwt');
/// const jwt = await getJwt({ server: 'myserver' });
/// ```
#[napi]
pub async fn get_jwt(options: Option<JwtOptions>) -> napi::Result<String> {
    let opts = convert_options(options)?;

    tokio::task::spawn_blocking(move || sso_jwt_lib::get_jwt(&opts))
        .await
        .map_err(|e| napi::Error::from_reason(format!("task join error: {e}")))?
        .map_err(|e| napi::Error::from_reason(format!("{e:#}")))
}

fn convert_options(options: Option<JwtOptions>) -> napi::Result<sso_jwt_lib::GetJwtOptions> {
    match options {
        None => Ok(sso_jwt_lib::GetJwtOptions::default()),
        Some(o) => {
            if let Some(level) = o.risk_level {
                if !(1..=3).contains(&level) {
                    return Err(napi::Error::from_reason(format!(
                        "risk_level must be between 1 and 3, got {level}"
                    )));
                }
            }
            Ok(sso_jwt_lib::GetJwtOptions {
            server: o.server,
            env: o.env,
            oauth_url: o.oauth_url,
            token_url: o.token_url,
            heartbeat_url: o.heartbeat_url,
            client_id: o.client_id,
            cache_name: o.cache_name,
            risk_level: o.risk_level.map(|v| v as u8),
            biometric: o.biometric,
            no_open: o.no_open,
            })
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn convert_options_rejects_out_of_range_risk_level() {
        let err = convert_options(Some(JwtOptions {
            risk_level: Some(255),
            ..JwtOptions::default()
        }))
        .unwrap_err();
        assert!(err.to_string().contains("risk_level"));
    }

    #[test]
    fn convert_options_accepts_valid_risk_level() {
        let opts = convert_options(Some(JwtOptions {
            risk_level: Some(3),
            ..JwtOptions::default()
        }))
        .unwrap();
        assert_eq!(opts.risk_level, Some(3));
    }
}
