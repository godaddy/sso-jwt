pub mod cache;
pub mod config;
pub mod jwt;
pub mod oauth;
pub mod secure_storage;

pub use config::Config;

/// Options for obtaining a JWT, matching the Node.js `getJwt` contract.
#[derive(Debug, Clone, Default)]
pub struct GetJwtOptions {
    /// SSO environment: "dev", "test", "ote", "prod" (default: from config or "prod")
    pub env: Option<String>,
    /// Override OAuth service URL
    pub oauth_url: Option<String>,
    /// Cache name for storing the encrypted token (default: from config or "default")
    pub cache_name: Option<String>,
    /// Risk level 1-3 (default: from config or 2)
    pub risk_level: Option<u8>,
    /// Require biometric for cache access (default: from config or false)
    pub biometric: Option<bool>,
    /// Don't auto-open browser (default: false)
    pub no_open: Option<bool>,
}

/// High-level function to obtain a JWT.
///
/// Loads configuration (file + env vars), applies the provided options,
/// initializes platform-specific secure storage, and resolves a token
/// from cache or via the OAuth Device Code flow.
///
/// This function matches the contract of the Node.js `getJwt()`.
pub fn get_jwt(options: &GetJwtOptions) -> anyhow::Result<String> {
    let mut config = Config::load()?;

    // Apply caller-provided overrides (highest priority)
    if let Some(ref env) = options.env {
        config.environment = env.clone();
    }
    if let Some(ref url) = options.oauth_url {
        config.oauth_url = Some(url.clone());
    }
    if let Some(ref name) = options.cache_name {
        config.cache_name = name.clone();
    }
    if let Some(rl) = options.risk_level {
        config.risk_level = rl;
    }
    if let Some(bio) = options.biometric {
        config.biometric = bio;
    }
    if let Some(no) = options.no_open {
        config.no_open = no;
    }

    let storage = secure_storage::platform_storage(config.biometric)?;
    cache::resolve_token(&config, storage.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options() {
        let opts = GetJwtOptions::default();
        assert!(opts.env.is_none());
        assert!(opts.oauth_url.is_none());
        assert!(opts.cache_name.is_none());
        assert!(opts.risk_level.is_none());
        assert!(opts.biometric.is_none());
        assert!(opts.no_open.is_none());
    }

    #[test]
    fn options_with_values() {
        let opts = GetJwtOptions {
            env: Some("dev".to_string()),
            risk_level: Some(3),
            ..Default::default()
        };
        assert_eq!(opts.env.as_deref(), Some("dev"));
        assert_eq!(opts.risk_level, Some(3));
        assert!(opts.oauth_url.is_none());
    }
}
