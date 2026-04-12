use anyhow::{bail, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

const DEFAULT_RISK_LEVEL: u8 = 2;
const DEFAULT_CACHE_NAME: &str = "default";
const DEFAULT_ENV_VAR: &str = "SSO_JWT";
const DEFAULT_CLIENT_ID: &str = "sso-jwt";
const DEFAULT_SERVER: &str = "default";

/// Resolved configuration after merging file, env vars, and CLI flags.
#[derive(Debug, Clone)]
pub struct Config {
    pub server: String,
    pub environment: Option<String>,
    pub oauth_url: String,
    pub heartbeat_url: Option<String>,
    pub client_id: String,
    pub env_var: String,
    pub risk_level: u8,
    pub biometric: bool,
    pub cache_name: String,
    pub no_open: bool,
    pub clear: bool,
}

/// On-disk TOML configuration (all fields optional).
#[derive(Debug, Deserialize, Default)]
struct FileConfig {
    default_server: Option<String>,
    risk_level: Option<u8>,
    biometric: Option<bool>,
    cache_name: Option<String>,
    servers: Option<HashMap<String, ServerFileConfig>>,
}

#[derive(Debug, Deserialize)]
struct ServerFileConfig {
    oauth_url: String,
    heartbeat_url: Option<String>,
    client_id: Option<String>,
    env_var: Option<String>,
    environments: Option<HashMap<String, EnvironmentFileConfig>>,
}

#[derive(Debug, Deserialize)]
struct EnvironmentFileConfig {
    oauth_url: Option<String>,
    heartbeat_url: Option<String>,
}

impl Config {
    /// Load config from file and environment variables.
    /// CLI flags are applied separately by the caller.
    /// After loading, call `resolve_server()` to finalize oauth_url/heartbeat_url
    /// from server profiles.
    pub fn load() -> Result<Self> {
        let fc = Self::load_file_config().unwrap_or_default();

        let mut cfg = Config {
            server: fc
                .default_server
                .unwrap_or_else(|| DEFAULT_SERVER.to_string()),
            environment: None,
            oauth_url: String::new(),
            heartbeat_url: None,
            client_id: DEFAULT_CLIENT_ID.to_string(),
            env_var: DEFAULT_ENV_VAR.to_string(),
            risk_level: fc.risk_level.unwrap_or(DEFAULT_RISK_LEVEL),
            biometric: fc.biometric.unwrap_or(false),
            cache_name: fc
                .cache_name
                .unwrap_or_else(|| DEFAULT_CACHE_NAME.to_string()),
            no_open: false,
            clear: false,
        };

        // Environment variables override file config
        if let Ok(v) = std::env::var("SSOJWT_SERVER") {
            cfg.server = v;
        }
        if let Ok(v) = std::env::var("SSOJWT_ENVIRONMENT") {
            cfg.environment = Some(v);
        }
        if let Ok(v) = std::env::var("SSOJWT_OAUTH_URL") {
            cfg.oauth_url = v;
        }
        if let Ok(v) = std::env::var("SSOJWT_HEARTBEAT_URL") {
            cfg.heartbeat_url = Some(v);
        }
        if let Ok(v) = std::env::var("SSOJWT_CLIENT_ID") {
            cfg.client_id = v;
        }
        if let Ok(v) = std::env::var("SSOJWT_ENV_VAR") {
            cfg.env_var = v;
        }
        if let Ok(v) = std::env::var("SSOJWT_RISK_LEVEL") {
            if let Ok(rl) = v.parse::<u8>() {
                cfg.risk_level = rl;
            }
        }
        if let Ok(v) = std::env::var("SSOJWT_BIOMETRIC") {
            cfg.biometric = v == "true" || v == "1";
        }
        if let Ok(v) = std::env::var("SSOJWT_CACHE_NAME") {
            cfg.cache_name = v;
        }

        Ok(cfg)
    }

    /// Resolve server profile from the config file.
    ///
    /// If `oauth_url` is already set (from env var or CLI override), this is
    /// "direct URL mode" and server resolution is skipped.
    ///
    /// Otherwise, looks up `self.server` in the file config's servers map,
    /// applies server-level settings, and then applies environment overrides
    /// if `self.environment` is set.
    pub fn resolve_server(&mut self) -> Result<()> {
        // Direct URL mode: oauth_url already set, skip server resolution
        if !self.oauth_url.is_empty() {
            return Ok(());
        }

        let fc = Self::load_file_config().unwrap_or_default();
        let servers = match fc.servers {
            Some(s) => s,
            None => {
                bail!(
                    "no server configured. Either set --oauth-url or configure a server in ~/.config/sso-jwt/config.toml"
                );
            }
        };

        let server_config = match servers.get(&self.server) {
            Some(sc) => sc,
            None => {
                bail!(
                    "no server configured. Either set --oauth-url or configure a server in ~/.config/sso-jwt/config.toml"
                );
            }
        };

        self.oauth_url = server_config.oauth_url.clone();
        self.heartbeat_url = server_config.heartbeat_url.clone();
        if let Some(ref cid) = server_config.client_id {
            self.client_id = cid.clone();
        }
        if let Some(ref ev) = server_config.env_var {
            self.env_var = ev.clone();
        }

        // Apply environment overrides if set
        if let Some(ref env_name) = self.environment {
            if let Some(ref envs) = server_config.environments {
                if let Some(env_config) = envs.get(env_name) {
                    if let Some(ref url) = env_config.oauth_url {
                        self.oauth_url = url.clone();
                    }
                    if let Some(ref url) = env_config.heartbeat_url {
                        self.heartbeat_url = Some(url.clone());
                    }
                }
            }
        }

        Ok(())
    }

    /// XDG-compliant config/cache directory.
    pub fn config_dir() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| {
                dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join(".config")
            })
            .join("sso-jwt")
    }

    pub fn config_file_path() -> PathBuf {
        Self::config_dir().join("config.toml")
    }

    pub fn cache_dir() -> PathBuf {
        Self::config_dir()
    }

    pub fn cache_file_path(&self) -> PathBuf {
        // Sanitize cache name: strip path separators and traversal sequences
        // to prevent writing outside the cache directory.
        let sanitized_cache: String = self.cache_name.replace(['/', '\\'], "").replace("..", "");
        let cache_part = if sanitized_cache.is_empty() {
            "default"
        } else {
            &sanitized_cache
        };

        // Sanitize server name the same way
        let sanitized_server: String = self.server.replace(['/', '\\'], "").replace("..", "");
        let server_part = if sanitized_server.is_empty() {
            "default"
        } else {
            &sanitized_server
        };

        let name = match &self.environment {
            Some(env) => {
                let sanitized_env: String = env.replace(['/', '\\'], "").replace("..", "");
                let env_part = if sanitized_env.is_empty() {
                    "default"
                } else {
                    &sanitized_env
                };
                format!("{server_part}-{env_part}-{cache_part}")
            }
            None => format!("{server_part}-{cache_part}"),
        };

        Self::cache_dir().join(format!("{name}.enc"))
    }

    fn load_file_config() -> Result<FileConfig> {
        let path = Self::config_file_path();
        let content = std::fs::read_to_string(path)?;
        let config: FileConfig = toml::from_str(&content)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mutex to serialize tests that read/write SSOJWT_* env vars via Config::load().
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    const SSOJWT_KEYS: [&str; 9] = [
        "SSOJWT_SERVER",
        "SSOJWT_ENVIRONMENT",
        "SSOJWT_OAUTH_URL",
        "SSOJWT_HEARTBEAT_URL",
        "SSOJWT_CLIENT_ID",
        "SSOJWT_ENV_VAR",
        "SSOJWT_RISK_LEVEL",
        "SSOJWT_BIOMETRIC",
        "SSOJWT_CACHE_NAME",
    ];

    /// Save current SSOJWT env vars, clear them, and return saved values.
    fn save_and_clear_env() -> Vec<Option<String>> {
        let saved: Vec<_> = SSOJWT_KEYS.iter().map(|k| std::env::var(k).ok()).collect();
        for key in &SSOJWT_KEYS {
            std::env::remove_var(key);
        }
        saved
    }

    /// Restore previously saved SSOJWT env vars.
    fn restore_env(saved: Vec<Option<String>>) {
        for (key, val) in SSOJWT_KEYS.iter().zip(saved) {
            match val {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }

    /// Helper to build a Config directly for tests (bypasses file/env loading).
    fn test_config() -> Config {
        Config {
            server: "default".to_string(),
            environment: None,
            oauth_url: String::new(),
            heartbeat_url: None,
            client_id: DEFAULT_CLIENT_ID.to_string(),
            env_var: DEFAULT_ENV_VAR.to_string(),
            risk_level: DEFAULT_RISK_LEVEL,
            biometric: false,
            cache_name: DEFAULT_CACHE_NAME.to_string(),
            no_open: false,
            clear: false,
        }
    }

    #[test]
    fn default_values() {
        let _lock = ENV_MUTEX.lock().expect("env mutex poisoned");
        let saved = save_and_clear_env();

        let cfg = Config::load().expect("Config::load should succeed");
        assert_eq!(cfg.server, "default");
        assert!(cfg.environment.is_none());
        assert_eq!(cfg.oauth_url, "");
        assert!(cfg.heartbeat_url.is_none());
        assert_eq!(cfg.client_id, "sso-jwt");
        assert_eq!(cfg.env_var, "SSO_JWT");
        assert_eq!(cfg.risk_level, 2);
        assert!(!cfg.biometric);
        assert_eq!(cfg.cache_name, "default");

        restore_env(saved);
    }

    #[test]
    fn direct_oauth_url_mode_skips_server_resolution() {
        let mut cfg = test_config();
        cfg.oauth_url = "https://auth.example.com/device".to_string();
        // resolve_server should succeed and not change the URL
        cfg.resolve_server().expect("resolve_server should succeed");
        assert_eq!(cfg.oauth_url, "https://auth.example.com/device");
    }

    #[test]
    fn missing_server_returns_error() {
        let mut cfg = test_config();
        cfg.server = "nonexistent".to_string();
        // oauth_url is empty and no config file, so resolve_server should fail
        let result = cfg.resolve_server();
        assert!(result.is_err());
        let err = result.expect_err("should fail");
        assert!(
            err.to_string().contains("no server configured"),
            "error should mention no server configured, got: {err}"
        );
    }

    #[test]
    fn parse_file_config_with_servers() {
        let toml_str = r#"
default_server = "myco"
risk_level = 3
biometric = true
cache_name = "work"

[servers.myco]
oauth_url = "https://auth.myco.com/device"
heartbeat_url = "https://auth.myco.com/heartbeat"
client_id = "myco-client"
env_var = "MYCO_JWT"

[servers.myco.environments.dev]
oauth_url = "https://auth.dev.myco.com/device"
heartbeat_url = "https://auth.dev.myco.com/heartbeat"

[servers.other]
oauth_url = "https://other.example.com/oauth"
"#;
        let fc: FileConfig = toml::from_str(toml_str).expect("valid TOML");
        assert_eq!(fc.default_server.as_deref(), Some("myco"));
        assert_eq!(fc.risk_level, Some(3));
        assert_eq!(fc.biometric, Some(true));
        assert_eq!(fc.cache_name.as_deref(), Some("work"));

        let servers = fc.servers.expect("servers should be present");
        assert_eq!(servers.len(), 2);

        let myco = servers.get("myco").expect("myco server should exist");
        assert_eq!(myco.oauth_url, "https://auth.myco.com/device");
        assert_eq!(
            myco.heartbeat_url.as_deref(),
            Some("https://auth.myco.com/heartbeat")
        );
        assert_eq!(myco.client_id.as_deref(), Some("myco-client"));
        assert_eq!(myco.env_var.as_deref(), Some("MYCO_JWT"));

        let envs = myco.environments.as_ref().expect("environments present");
        let dev = envs.get("dev").expect("dev environment");
        assert_eq!(
            dev.oauth_url.as_deref(),
            Some("https://auth.dev.myco.com/device")
        );
        assert_eq!(
            dev.heartbeat_url.as_deref(),
            Some("https://auth.dev.myco.com/heartbeat")
        );

        let other = servers.get("other").expect("other server should exist");
        assert_eq!(other.oauth_url, "https://other.example.com/oauth");
        assert!(other.heartbeat_url.is_none());
        assert!(other.client_id.is_none());
    }

    #[test]
    fn parse_file_config_empty() {
        let fc: FileConfig = toml::from_str("").expect("empty config");
        assert!(fc.default_server.is_none());
        assert!(fc.risk_level.is_none());
        assert!(fc.servers.is_none());
    }

    #[test]
    fn parse_file_config_partial() {
        let toml_str = r#"risk_level = 1"#;
        let fc: FileConfig = toml::from_str(toml_str).expect("partial config");
        assert!(fc.default_server.is_none());
        assert_eq!(fc.risk_level, Some(1));
    }

    #[test]
    fn env_var_overrides_server() {
        let _lock = ENV_MUTEX.lock().expect("env mutex poisoned");
        let saved = save_and_clear_env();

        std::env::set_var("SSOJWT_SERVER", "custom-server");
        let cfg = Config::load().expect("Config::load should succeed");
        assert_eq!(cfg.server, "custom-server");

        restore_env(saved);
    }

    #[test]
    fn env_var_overrides_environment() {
        let _lock = ENV_MUTEX.lock().expect("env mutex poisoned");
        let saved = save_and_clear_env();

        std::env::set_var("SSOJWT_ENVIRONMENT", "staging");
        let cfg = Config::load().expect("Config::load should succeed");
        assert_eq!(cfg.environment.as_deref(), Some("staging"));

        restore_env(saved);
    }

    #[test]
    fn env_var_overrides_oauth_url() {
        let _lock = ENV_MUTEX.lock().expect("env mutex poisoned");
        let saved = save_and_clear_env();

        std::env::set_var("SSOJWT_OAUTH_URL", "https://custom.example.com/oauth");
        let cfg = Config::load().expect("Config::load should succeed");
        assert_eq!(cfg.oauth_url, "https://custom.example.com/oauth");

        restore_env(saved);
    }

    #[test]
    fn env_var_overrides_client_id() {
        let _lock = ENV_MUTEX.lock().expect("env mutex poisoned");
        let saved = save_and_clear_env();

        std::env::set_var("SSOJWT_CLIENT_ID", "my-custom-client");
        let cfg = Config::load().expect("Config::load should succeed");
        assert_eq!(cfg.client_id, "my-custom-client");

        restore_env(saved);
    }

    #[test]
    fn env_var_biometric_values() {
        let _lock = ENV_MUTEX.lock().expect("env mutex poisoned");
        let saved = save_and_clear_env();

        // "true" enables biometric
        std::env::set_var("SSOJWT_BIOMETRIC", "true");
        let cfg = Config::load().expect("Config::load should succeed");
        assert!(
            cfg.biometric,
            "SSOJWT_BIOMETRIC=true should enable biometric"
        );

        // "1" enables biometric
        std::env::set_var("SSOJWT_BIOMETRIC", "1");
        let cfg = Config::load().expect("Config::load should succeed");
        assert!(cfg.biometric, "SSOJWT_BIOMETRIC=1 should enable biometric");

        // "false" disables biometric
        std::env::set_var("SSOJWT_BIOMETRIC", "false");
        let cfg = Config::load().expect("Config::load should succeed");
        assert!(
            !cfg.biometric,
            "SSOJWT_BIOMETRIC=false should disable biometric"
        );

        restore_env(saved);
    }

    #[test]
    fn unknown_toml_keys_ignored() {
        let toml_str = r#"
risk_level = 1
unknown_key = "should be ignored"
another_unknown = 42
"#;
        let fc: FileConfig =
            toml::from_str(toml_str).expect("unknown keys should be silently ignored");
        assert_eq!(fc.risk_level, Some(1));
    }

    #[test]
    fn config_dir_ends_in_sso_jwt() {
        let dir = Config::config_dir();
        assert!(
            dir.ends_with("sso-jwt"),
            "config_dir should end with sso-jwt, got: {}",
            dir.display()
        );
    }

    #[test]
    fn config_file_path_ends_in_config_toml() {
        let path = Config::config_file_path();
        assert!(
            path.to_string_lossy().ends_with("config.toml"),
            "config_file_path should end with config.toml, got: {}",
            path.display()
        );
    }

    #[test]
    fn cache_path_namespaced_by_server() {
        let mut cfg = test_config();
        cfg.server = "myserver".to_string();
        cfg.cache_name = "default".to_string();
        let path = cfg.cache_file_path();
        let filename = path
            .file_name()
            .expect("should have filename")
            .to_string_lossy();
        assert_eq!(filename, "myserver-default.enc");
    }

    #[test]
    fn cache_path_namespaced_by_server_and_environment() {
        let mut cfg = test_config();
        cfg.server = "myserver".to_string();
        cfg.environment = Some("dev".to_string());
        cfg.cache_name = "default".to_string();
        let path = cfg.cache_file_path();
        let filename = path
            .file_name()
            .expect("should have filename")
            .to_string_lossy();
        assert_eq!(filename, "myserver-dev-default.enc");
    }

    #[test]
    fn cache_path_with_custom_cache_name() {
        let mut cfg = test_config();
        cfg.server = "co".to_string();
        cfg.cache_name = "myenv".to_string();
        let path = cfg.cache_file_path();
        let filename = path
            .file_name()
            .expect("should have filename")
            .to_string_lossy();
        assert_eq!(filename, "co-myenv.enc");
    }

    #[test]
    fn cache_name_path_traversal_stripped() {
        let mut cfg = test_config();
        cfg.cache_name = "../../etc/passwd".to_string();
        let path = cfg.cache_file_path();
        let filename = path
            .file_name()
            .expect("should have filename")
            .to_string_lossy();
        assert!(
            !filename.contains(".."),
            "path traversal should be stripped: {filename}"
        );
        assert!(
            !filename.contains('/'),
            "slashes should be stripped: {filename}"
        );
        assert!(
            filename.ends_with(".enc"),
            "should still end in .enc: {filename}"
        );

        // Pure traversal with nothing left should fall back to "default"
        cfg.cache_name = "../..".to_string();
        let path = cfg.cache_file_path();
        let filename = path
            .file_name()
            .expect("should have filename")
            .to_string_lossy();
        assert!(
            filename.ends_with("default.enc"),
            "pure traversal should fall back to default: {filename}"
        );
    }

    #[test]
    fn cache_name_backslash_stripped() {
        let mut cfg = test_config();
        cfg.cache_name = r"..\..\windows\system32".to_string();
        let path = cfg.cache_file_path();
        let filename = path
            .file_name()
            .expect("should have filename")
            .to_string_lossy();
        assert!(
            !filename.contains('\\'),
            "backslashes should be stripped: {filename}"
        );
        assert!(
            !filename.contains(".."),
            "traversal should be stripped: {filename}"
        );
    }

    #[test]
    fn cache_name_normal_values_unchanged() {
        let mut cfg = test_config();
        cfg.server = "co".to_string();
        cfg.cache_name = "my-project".to_string();
        let path = cfg.cache_file_path();
        let filename = path
            .file_name()
            .expect("should have filename")
            .to_string_lossy();
        assert_eq!(filename, "co-my-project.enc");
    }

    #[test]
    fn server_path_traversal_stripped() {
        let mut cfg = test_config();
        cfg.server = "../../etc/evil".to_string();
        let path = cfg.cache_file_path();
        let filename = path
            .file_name()
            .expect("should have filename")
            .to_string_lossy();
        assert!(
            !filename.contains(".."),
            "server traversal should be stripped: {filename}"
        );
        assert!(
            !filename.contains('/'),
            "server slashes should be stripped: {filename}"
        );
    }

    #[test]
    fn config_with_multiple_servers() {
        let toml_str = r#"
default_server = "alpha"

[servers.alpha]
oauth_url = "https://alpha.example.com/oauth"
client_id = "alpha-id"

[servers.beta]
oauth_url = "https://beta.example.com/oauth"
heartbeat_url = "https://beta.example.com/heartbeat"
client_id = "beta-id"
env_var = "BETA_TOKEN"

[servers.gamma]
oauth_url = "https://gamma.example.com/oauth"

[servers.gamma.environments.staging]
oauth_url = "https://staging.gamma.example.com/oauth"
"#;
        let fc: FileConfig = toml::from_str(toml_str).expect("valid multi-server TOML");
        let servers = fc.servers.expect("servers present");
        assert_eq!(servers.len(), 3);
        assert!(servers.contains_key("alpha"));
        assert!(servers.contains_key("beta"));
        assert!(servers.contains_key("gamma"));
    }
}
