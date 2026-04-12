pub mod cache;
pub mod config;
pub mod jwt;
pub mod oauth;
pub mod secure_storage;

pub use config::Config;

/// Options for obtaining a JWT, matching the Node.js `getJwt` contract.
#[derive(Debug, Clone, Default)]
pub struct GetJwtOptions {
    /// Server profile name (default: from config or "default")
    pub server: Option<String>,
    /// Environment within the server profile
    pub env: Option<String>,
    /// Override OAuth service URL (bypasses server profile resolution)
    pub oauth_url: Option<String>,
    /// Override heartbeat URL
    pub heartbeat_url: Option<String>,
    /// Override client ID
    pub client_id: Option<String>,
    /// Cache name for storing the encrypted token (default: from config or "default")
    pub cache_name: Option<String>,
    /// Risk level 1-3 (default: from config or 2)
    pub risk_level: Option<u8>,
    /// Require biometric for cache access (default: from config or false)
    pub biometric: Option<bool>,
    /// Don't auto-open browser (default: false)
    pub no_open: Option<bool>,
    /// Environment variable name override
    pub env_var: Option<String>,
}

/// High-level function to obtain a JWT.
///
/// Loads configuration (file + env vars), applies the provided options,
/// resolves server profiles, initializes platform-specific secure storage,
/// and resolves a token from cache or via the OAuth Device Code flow.
///
/// This function matches the contract of the Node.js `getJwt()`.
pub fn get_jwt(options: &GetJwtOptions) -> anyhow::Result<String> {
    let mut config = Config::load()?;

    // Apply caller-provided overrides before server resolution
    if let Some(ref s) = options.server {
        config.server = s.clone();
    }
    if let Some(ref e) = options.env {
        config.environment = Some(e.clone());
    }
    if let Some(ref u) = options.oauth_url {
        config.oauth_url = u.clone();
    }
    if let Some(ref u) = options.heartbeat_url {
        config.heartbeat_url = Some(u.clone());
    }
    if let Some(ref c) = options.client_id {
        config.client_id = c.clone();
    }
    if let Some(ref n) = options.cache_name {
        config.cache_name = n.clone();
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
    if let Some(ref ev) = options.env_var {
        config.env_var = ev.clone();
    }

    // Resolve server profile (skipped if oauth_url already set directly)
    config.resolve_server()?;

    let storage = secure_storage::platform_storage(config.biometric)?;
    cache::resolve_token(&config, storage.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options() {
        let opts = GetJwtOptions::default();
        assert!(opts.server.is_none());
        assert!(opts.env.is_none());
        assert!(opts.oauth_url.is_none());
        assert!(opts.heartbeat_url.is_none());
        assert!(opts.client_id.is_none());
        assert!(opts.cache_name.is_none());
        assert!(opts.risk_level.is_none());
        assert!(opts.biometric.is_none());
        assert!(opts.no_open.is_none());
        assert!(opts.env_var.is_none());
    }

    #[test]
    fn options_with_values() {
        let opts = GetJwtOptions {
            server: Some("myco".to_string()),
            env: Some("dev".to_string()),
            risk_level: Some(3),
            ..Default::default()
        };
        assert_eq!(opts.server.as_deref(), Some("myco"));
        assert_eq!(opts.env.as_deref(), Some("dev"));
        assert_eq!(opts.risk_level, Some(3));
        assert!(opts.oauth_url.is_none());
        assert!(opts.heartbeat_url.is_none());
        assert!(opts.client_id.is_none());
    }

    #[test]
    fn options_with_direct_url() {
        let opts = GetJwtOptions {
            oauth_url: Some("https://auth.example.com/device".to_string()),
            heartbeat_url: Some("https://auth.example.com/heartbeat".to_string()),
            client_id: Some("my-client".to_string()),
            env_var: Some("MY_JWT".to_string()),
            ..Default::default()
        };
        assert_eq!(
            opts.oauth_url.as_deref(),
            Some("https://auth.example.com/device")
        );
        assert_eq!(
            opts.heartbeat_url.as_deref(),
            Some("https://auth.example.com/heartbeat")
        );
        assert_eq!(opts.client_id.as_deref(), Some("my-client"));
        assert_eq!(opts.env_var.as_deref(), Some("MY_JWT"));
        assert!(opts.server.is_none());
    }
}
