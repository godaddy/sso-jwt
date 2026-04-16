pub mod cache;
pub mod config;
pub mod jwt;
pub mod oauth;

pub use config::{Config, EnvironmentFileConfig, FileConfig, ServerFileConfig};

/// Options for obtaining a JWT.
#[derive(Debug, Clone, Default)]
pub struct GetJwtOptions {
    /// Server profile name (default: from config or "default")
    pub server: Option<String>,
    /// Environment within the server profile
    pub env: Option<String>,
    /// Override OAuth service URL (bypasses server profile resolution)
    pub oauth_url: Option<String>,
    /// Override token polling URL (separate from device authorization endpoint)
    pub token_url: Option<String>,
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
}

/// High-level function to obtain a JWT.
///
/// Loads configuration (file + env vars), applies the provided options,
/// resolves server profiles, initializes platform-specific secure storage,
/// and resolves a token from cache or via the OAuth Device Code flow.
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
    if let Some(ref u) = options.token_url {
        config.token_url = Some(u.clone());
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

    // Resolve server profile (skipped if oauth_url already set directly)
    config.resolve_server()?;

    use enclaveapp_app_storage::{create_encryption_storage, AccessPolicy, StorageConfig};

    let policy = if config.biometric {
        AccessPolicy::BiometricOnly
    } else {
        AccessPolicy::None
    };
    let storage = create_encryption_storage(StorageConfig {
        app_name: "sso-jwt".into(),
        key_label: "cache-key".into(),
        access_policy: policy,
        extra_bridge_paths: vec![],
        keys_dir: None,
        force_keyring: false,
    })?;
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
        assert!(opts.token_url.is_none());
        assert!(opts.heartbeat_url.is_none());
        assert!(opts.client_id.is_none());
        assert!(opts.cache_name.is_none());
        assert!(opts.risk_level.is_none());
        assert!(opts.biometric.is_none());
        assert!(opts.no_open.is_none());
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
    }

    #[test]
    fn options_with_direct_url() {
        let opts = GetJwtOptions {
            oauth_url: Some("https://auth.example.com/device".to_string()),
            token_url: Some("https://auth.example.com/token".to_string()),
            heartbeat_url: Some("https://auth.example.com/heartbeat".to_string()),
            client_id: Some("my-client".to_string()),
            ..Default::default()
        };
        assert_eq!(
            opts.oauth_url.as_deref(),
            Some("https://auth.example.com/device")
        );
        assert_eq!(
            opts.token_url.as_deref(),
            Some("https://auth.example.com/token")
        );
        assert_eq!(opts.client_id.as_deref(), Some("my-client"));
        assert!(opts.server.is_none());
    }

    #[test]
    fn options_with_cache_name() {
        let opts = GetJwtOptions {
            cache_name: Some("my-project".to_string()),
            ..Default::default()
        };
        assert_eq!(opts.cache_name.as_deref(), Some("my-project"));
    }

    #[test]
    fn options_with_biometric_and_no_open() {
        let opts = GetJwtOptions {
            biometric: Some(true),
            no_open: Some(true),
            ..Default::default()
        };
        assert_eq!(opts.biometric, Some(true));
        assert_eq!(opts.no_open, Some(true));
    }

    #[test]
    fn options_clone() {
        let opts = GetJwtOptions {
            server: Some("test".to_string()),
            risk_level: Some(3),
            ..Default::default()
        };
        let cloned = opts.clone();
        assert_eq!(cloned.server, opts.server);
        assert_eq!(cloned.risk_level, opts.risk_level);
    }

    #[test]
    fn options_debug() {
        let opts = GetJwtOptions::default();
        let debug = format!("{opts:?}");
        assert!(debug.contains("GetJwtOptions"));
    }

    #[test]
    fn re_exports_config_types() {
        // Verify that the re-exported types are accessible
        let fc = FileConfig::default();
        assert!(fc.default_server.is_none());
    }
}
