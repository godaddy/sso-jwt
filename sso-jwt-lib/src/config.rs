use anyhow::{anyhow, bail, Result};
use enclaveapp_core::metadata;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[cfg(test)]
pub(crate) static TEST_ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

const DEFAULT_RISK_LEVEL: u8 = 2;
const DEFAULT_CACHE_NAME: &str = "default";
const DEFAULT_CLIENT_ID: &str = "sso-jwt";
const DEFAULT_SERVER: &str = "default";

/// Resolved configuration after merging file, env vars, and CLI flags.
#[derive(Debug, Clone)]
pub struct Config {
    pub server: String,
    pub environment: Option<String>,
    pub oauth_url: String,
    pub token_url: Option<String>,
    pub heartbeat_url: Option<String>,
    pub client_id: String,
    pub risk_level: u8,
    pub biometric: bool,
    pub cache_name: String,
    pub no_open: bool,
    pub clear: bool,
}

/// On-disk TOML configuration (all fields optional).
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct FileConfig {
    pub default_server: Option<String>,
    pub risk_level: Option<u8>,
    pub biometric: Option<bool>,
    pub cache_name: Option<String>,
    pub servers: Option<HashMap<String, ServerFileConfig>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerFileConfig {
    pub client_id: Option<String>,
    pub environments: Option<HashMap<String, EnvironmentFileConfig>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EnvironmentFileConfig {
    pub default: Option<bool>,
    pub oauth_url: Option<String>,
    pub token_url: Option<String>,
    pub heartbeat_url: Option<String>,
}

impl Config {
    fn encode_cache_component(value: &str) -> String {
        let value = if value.is_empty() { "default" } else { value };
        let mut encoded = String::with_capacity(value.len());

        for byte in value.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => {
                    encoded.push(byte as char);
                }
                _ => {
                    encoded.push('~');
                    encoded.push(
                        char::from_digit(u32::from(byte >> 4), 16)
                            .unwrap_or('0')
                            .to_ascii_uppercase(),
                    );
                    encoded.push(
                        char::from_digit(u32::from(byte & 0x0f), 16)
                            .unwrap_or('0')
                            .to_ascii_uppercase(),
                    );
                }
            }
        }

        encoded
    }

    fn legacy_cache_component(value: &str) -> String {
        let sanitized = value.replace(['/', '\\'], "").replace("..", "");
        if sanitized.is_empty() {
            "default".to_string()
        } else {
            sanitized
        }
    }

    fn validate_endpoint_url(name: &str, value: &str) -> Result<()> {
        let parsed =
            reqwest::Url::parse(value).map_err(|error| anyhow!("invalid {name}: {error}"))?;
        if parsed.scheme() != "https" {
            bail!("{name} must use HTTPS: {value}");
        }
        Ok(())
    }

    fn validate_endpoint_urls(&self) -> Result<()> {
        if !self.oauth_url.is_empty() {
            Self::validate_endpoint_url("oauth_url", &self.oauth_url)?;
        }
        if let Some(token_url) = self.token_url.as_deref() {
            Self::validate_endpoint_url("token_url", token_url)?;
        }
        if let Some(heartbeat_url) = self.heartbeat_url.as_deref() {
            Self::validate_endpoint_url("heartbeat_url", heartbeat_url)?;
        }
        Ok(())
    }

    /// Load config from file and environment variables.
    /// CLI flags are applied separately by the caller.
    /// After loading, call `resolve_server()` to finalize oauth_url/heartbeat_url
    /// from server profiles.
    pub fn load() -> Result<Self> {
        let fc = Self::load_file_config_if_exists()?.unwrap_or_default();

        let mut cfg = Config {
            server: fc
                .default_server
                .unwrap_or_else(|| DEFAULT_SERVER.to_string()),
            environment: None,
            oauth_url: String::new(),
            token_url: None,
            heartbeat_url: None,
            client_id: DEFAULT_CLIENT_ID.to_string(),
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
        if let Ok(v) = std::env::var("SSOJWT_TOKEN_URL") {
            cfg.token_url = Some(v);
        }
        if let Ok(v) = std::env::var("SSOJWT_HEARTBEAT_URL") {
            cfg.heartbeat_url = Some(v);
        }
        if let Ok(v) = std::env::var("SSOJWT_CLIENT_ID") {
            cfg.client_id = v;
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
    /// picks the environment (explicit name, or the one marked `default = true`),
    /// and pulls `oauth_url` / `heartbeat_url` from that environment.
    /// `client_id` comes from the server level.
    pub fn resolve_server(&mut self) -> Result<()> {
        // Direct URL mode: oauth_url already set, skip server resolution
        if !self.oauth_url.is_empty() {
            self.validate_endpoint_urls()?;
            return Ok(());
        }

        let fc = Self::load_file_config_if_exists()?.ok_or_else(|| {
            anyhow::anyhow!(
                "no server configured. Either set --oauth-url or configure a server in ~/.config/sso-jwt/config.toml"
            )
        })?;
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

        // Apply server-level settings
        if self.client_id == DEFAULT_CLIENT_ID {
            if let Some(ref cid) = server_config.client_id {
                self.client_id = cid.clone();
            }
        }

        // Resolve the environment
        let envs = match server_config.environments {
            Some(ref e) if !e.is_empty() => e,
            _ => {
                bail!(
                    "server '{}' has no environments configured. Add at least one environment with an oauth_url.",
                    self.server
                );
            }
        };

        let (env_name, env_config) = if let Some(ref requested) = self.environment {
            // Explicit environment requested
            match envs.get(requested.as_str()) {
                Some(ec) => (requested.clone(), ec),
                None => {
                    bail!(
                        "environment '{}' not found in server '{}'. Available: {}",
                        requested,
                        self.server,
                        envs.keys().cloned().collect::<Vec<_>>().join(", ")
                    );
                }
            }
        } else {
            // Find the default environment
            let default_env = envs.iter().find(|(_, ec)| ec.default == Some(true));
            match default_env {
                Some((name, ec)) => (name.clone(), ec),
                None => {
                    bail!(
                        "no default environment for server '{}'. Set default = true on one environment, or use --environment.",
                        self.server
                    );
                }
            }
        };

        // Set the environment name so cache paths are scoped correctly
        if self.environment.is_none() {
            self.environment = Some(env_name);
        }

        self.oauth_url = match env_config.oauth_url {
            Some(ref url) => url.clone(),
            None => {
                bail!("oauth_url is required on the environment but is missing");
            }
        };
        if self.token_url.is_none() {
            self.token_url = env_config.token_url.clone();
        }
        if self.heartbeat_url.is_none() {
            self.heartbeat_url = env_config.heartbeat_url.clone();
        }

        self.validate_endpoint_urls()?;
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
        let server = Self::encode_cache_component(&self.server);
        let cache = Self::encode_cache_component(&self.cache_name);
        let stem = match &self.environment {
            Some(environment) => format!(
                "server={server}--env={}--cache={cache}",
                Self::encode_cache_component(environment)
            ),
            None => format!("server={server}--cache={cache}"),
        };

        Self::cache_dir().join(format!("{stem}.enc"))
    }

    pub(crate) fn legacy_cache_file_path(&self) -> PathBuf {
        let cache_part = Self::legacy_cache_component(&self.cache_name);
        let server_part = Self::legacy_cache_component(&self.server);
        let stem = match &self.environment {
            Some(environment) => {
                let environment = Self::legacy_cache_component(environment);
                format!("{server_part}-{environment}-{cache_part}")
            }
            None => format!("{server_part}-{cache_part}"),
        };

        Self::cache_dir().join(format!("{stem}.enc"))
    }

    pub(crate) fn cache_lookup_paths(&self) -> Vec<PathBuf> {
        let primary = self.cache_file_path();
        let legacy = self.legacy_cache_file_path();
        if legacy == primary {
            vec![primary]
        } else {
            vec![primary, legacy]
        }
    }

    fn load_file_config_if_exists() -> Result<Option<FileConfig>> {
        let path = Self::config_file_path();
        match std::fs::read_to_string(path) {
            Ok(content) => Ok(Some(toml::from_str(&content)?)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    /// Load the on-disk file config, returning defaults if the file is missing.
    pub fn load_file_config_public() -> Result<FileConfig> {
        Ok(Self::load_file_config_if_exists()?.unwrap_or_default())
    }

    /// Write a `FileConfig` back to the config file as TOML.
    pub fn save_file_config(fc: &FileConfig) -> Result<()> {
        let path = Self::config_file_path();
        let dir = Self::config_dir();
        std::fs::create_dir_all(&dir)?;
        let content = toml::to_string_pretty(fc)?;
        metadata::atomic_write(&path, content.as_bytes())?;
        #[cfg(unix)]
        metadata::restrict_file_permissions(&path)?;
        Ok(())
    }

    /// Add a server from a TOML string (the flat remote config format).
    ///
    /// Parses `toml_content` as a `ServerFileConfig`, merges it into the
    /// existing file config under the given `label`, optionally sets
    /// `default_server`, and saves.
    pub fn add_server_from_toml(
        label: &str,
        toml_content: &str,
        set_default: bool,
        force: bool,
    ) -> Result<()> {
        let server_config: ServerFileConfig = toml::from_str(toml_content)?;

        let mut fc = Self::load_file_config_public()?;
        let servers = fc.servers.get_or_insert_with(HashMap::new);

        if servers.contains_key(label) && !force {
            bail!(
                "server '{}' already exists. Use --force to overwrite.",
                label
            );
        }

        servers.insert(label.to_string(), server_config);

        if set_default {
            fc.default_server = Some(label.to_string());
        }

        Self::save_file_config(&fc)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SSOJWT_KEYS: [&str; 9] = [
        "SSOJWT_SERVER",
        "SSOJWT_ENVIRONMENT",
        "SSOJWT_OAUTH_URL",
        "SSOJWT_TOKEN_URL",
        "SSOJWT_HEARTBEAT_URL",
        "SSOJWT_CLIENT_ID",
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

    struct TestEnvGuard {
        saved: Vec<Option<String>>,
        prev_xdg: Option<String>,
        prev_home: Option<String>,
        _dir: tempfile::TempDir,
    }

    impl Drop for TestEnvGuard {
        fn drop(&mut self) {
            restore_env(std::mem::take(&mut self.saved));
            match &self.prev_xdg {
                Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
            match &self.prev_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    fn isolated_env_guard() -> TestEnvGuard {
        let saved = save_and_clear_env();
        let prev_xdg = std::env::var("XDG_CONFIG_HOME").ok();
        let prev_home = std::env::var("HOME").ok();
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("XDG_CONFIG_HOME", dir.path());
        std::env::set_var("HOME", dir.path());
        TestEnvGuard {
            saved,
            prev_xdg,
            prev_home,
            _dir: dir,
        }
    }

    /// Helper to build a Config directly for tests (bypasses file/env loading).
    fn test_config() -> Config {
        Config {
            server: "default".to_string(),
            environment: None,
            oauth_url: String::new(),
            token_url: None,
            heartbeat_url: None,
            client_id: DEFAULT_CLIENT_ID.to_string(),
            risk_level: DEFAULT_RISK_LEVEL,
            biometric: false,
            cache_name: DEFAULT_CACHE_NAME.to_string(),
            no_open: false,
            clear: false,
        }
    }

    #[test]
    fn default_values() {
        let _lock = TEST_ENV_MUTEX.lock().expect("env mutex poisoned");
        let _guard = isolated_env_guard();

        let cfg = Config::load().expect("Config::load should succeed");
        assert_eq!(cfg.server, "default");
        assert!(cfg.environment.is_none());
        assert_eq!(cfg.oauth_url, "");
        assert!(cfg.token_url.is_none());
        assert!(cfg.heartbeat_url.is_none());
        assert_eq!(cfg.client_id, "sso-jwt");
        assert_eq!(cfg.risk_level, 2);
        assert!(!cfg.biometric);
        assert_eq!(cfg.cache_name, "default");
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
    fn direct_oauth_url_mode_rejects_cleartext() {
        let mut cfg = test_config();
        cfg.oauth_url = "http://auth.example.com/device".to_string();

        let error = cfg
            .resolve_server()
            .expect_err("cleartext oauth_url should fail");
        assert!(error.to_string().contains("oauth_url must use HTTPS"));
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
client_id = "myco-client"

[servers.myco.environments.prod]
default = true
oauth_url = "https://auth.myco.com/device"
heartbeat_url = "https://auth.myco.com/heartbeat"

[servers.myco.environments.dev]
oauth_url = "https://auth.dev.myco.com/device"
heartbeat_url = "https://auth.dev.myco.com/heartbeat"

[servers.other]

[servers.other.environments.prod]
default = true
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
        assert_eq!(myco.client_id.as_deref(), Some("myco-client"));

        let envs = myco.environments.as_ref().expect("environments present");
        let prod = envs.get("prod").expect("prod environment");
        assert_eq!(prod.default, Some(true));
        assert_eq!(
            prod.oauth_url.as_deref(),
            Some("https://auth.myco.com/device")
        );
        assert_eq!(
            prod.heartbeat_url.as_deref(),
            Some("https://auth.myco.com/heartbeat")
        );

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
        assert!(other.client_id.is_none());
        let other_envs = other.environments.as_ref().expect("other envs present");
        let other_prod = other_envs.get("prod").expect("other prod env");
        assert_eq!(
            other_prod.oauth_url.as_deref(),
            Some("https://other.example.com/oauth")
        );
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
        let _lock = TEST_ENV_MUTEX.lock().expect("env mutex poisoned");
        let _guard = isolated_env_guard();

        std::env::set_var("SSOJWT_SERVER", "custom-server");
        let cfg = Config::load().expect("Config::load should succeed");
        assert_eq!(cfg.server, "custom-server");
    }

    #[test]
    fn env_var_overrides_environment() {
        let _lock = TEST_ENV_MUTEX.lock().expect("env mutex poisoned");
        let _guard = isolated_env_guard();

        std::env::set_var("SSOJWT_ENVIRONMENT", "staging");
        let cfg = Config::load().expect("Config::load should succeed");
        assert_eq!(cfg.environment.as_deref(), Some("staging"));
    }

    #[test]
    fn env_var_overrides_oauth_url() {
        let _lock = TEST_ENV_MUTEX.lock().expect("env mutex poisoned");
        let _guard = isolated_env_guard();

        std::env::set_var("SSOJWT_OAUTH_URL", "https://custom.example.com/oauth");
        let cfg = Config::load().expect("Config::load should succeed");
        assert_eq!(cfg.oauth_url, "https://custom.example.com/oauth");
    }

    #[test]
    fn env_var_cleartext_token_url_is_rejected() {
        let _lock = TEST_ENV_MUTEX.lock().expect("env mutex poisoned");
        let _guard = isolated_env_guard();

        std::env::set_var("SSOJWT_OAUTH_URL", "https://custom.example.com/oauth");
        std::env::set_var("SSOJWT_TOKEN_URL", "http://custom.example.com/token");

        let mut cfg = Config::load().expect("Config::load should succeed");
        let error = cfg
            .resolve_server()
            .expect_err("cleartext token_url should fail");
        assert!(error.to_string().contains("token_url must use HTTPS"));
    }

    #[test]
    fn env_var_overrides_client_id() {
        let _lock = TEST_ENV_MUTEX.lock().expect("env mutex poisoned");
        let _guard = isolated_env_guard();

        std::env::set_var("SSOJWT_CLIENT_ID", "my-custom-client");
        let cfg = Config::load().expect("Config::load should succeed");
        assert_eq!(cfg.client_id, "my-custom-client");
    }

    #[test]
    fn env_var_biometric_values() {
        let _lock = TEST_ENV_MUTEX.lock().expect("env mutex poisoned");
        let _guard = isolated_env_guard();

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
        assert_eq!(filename, "server=myserver--cache=default.enc");
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
        assert_eq!(filename, "server=myserver--env=dev--cache=default.enc");
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
        assert_eq!(filename, "server=co--cache=myenv.enc");
    }

    #[test]
    fn cache_name_path_traversal_is_encoded_without_aliasing() {
        let mut cfg = test_config();
        cfg.cache_name = "../../etc/passwd".to_string();
        let path = cfg.cache_file_path();
        let filename = path
            .file_name()
            .expect("should have filename")
            .to_string_lossy();
        assert!(
            !filename.contains('/'),
            "encoded filename should not contain path separators: {filename}"
        );
        assert!(
            filename.contains("~2E~2E~2F"),
            "path traversal bytes should be encoded, not collapsed: {filename}"
        );
        assert!(
            filename.ends_with(".enc"),
            "should still end in .enc: {filename}"
        );

        let mut alias_cfg = test_config();
        alias_cfg.cache_name = "etcpasswd".to_string();
        assert_ne!(cfg.cache_file_path(), alias_cfg.cache_file_path());
    }

    #[test]
    fn cache_name_backslash_is_encoded() {
        let mut cfg = test_config();
        cfg.cache_name = r"..\..\windows\system32".to_string();
        let path = cfg.cache_file_path();
        let filename = path
            .file_name()
            .expect("should have filename")
            .to_string_lossy();
        assert!(
            !filename.contains('\\'),
            "backslashes should not appear literally: {filename}"
        );
        assert!(
            filename.contains("~5C"),
            "backslashes should be encoded: {filename}"
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
        assert_eq!(filename, "server=co--cache=my-project.enc");
    }

    #[test]
    fn server_path_traversal_is_encoded_without_colliding() {
        let mut cfg = test_config();
        cfg.server = "../../etc/evil".to_string();
        let path = cfg.cache_file_path();
        let filename = path
            .file_name()
            .expect("should have filename")
            .to_string_lossy();
        assert!(
            !filename.contains('/'),
            "server traversal bytes should not create separators: {filename}"
        );
        assert!(
            filename.contains("~2E~2E~2F"),
            "server traversal bytes should be encoded: {filename}"
        );
    }

    #[test]
    fn cache_path_distinguishes_escaped_components() {
        let mut cfg_a = test_config();
        cfg_a.server = "a/b".to_string();
        cfg_a.cache_name = "prod".to_string();

        let mut cfg_b = test_config();
        cfg_b.server = "ab".to_string();
        cfg_b.cache_name = "prod".to_string();

        assert_ne!(cfg_a.cache_file_path(), cfg_b.cache_file_path());
        assert_ne!(cfg_a.legacy_cache_file_path(), cfg_a.cache_file_path());
        assert_eq!(cfg_a.cache_lookup_paths().len(), 2);
    }

    #[test]
    fn config_with_multiple_servers() {
        let toml_str = r#"
default_server = "alpha"

[servers.alpha]
client_id = "alpha-id"

[servers.alpha.environments.prod]
default = true
oauth_url = "https://alpha.example.com/oauth"

[servers.beta]
client_id = "beta-id"

[servers.beta.environments.prod]
default = true
oauth_url = "https://beta.example.com/oauth"
heartbeat_url = "https://beta.example.com/heartbeat"

[servers.gamma]

[servers.gamma.environments.prod]
default = true
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

    #[test]
    fn parse_file_config_with_token_url() {
        let toml_str = r#"
[servers.github]
client_id = "gh-client-id"

[servers.github.environments.prod]
default = true
oauth_url = "https://github.com/login/device/code"
token_url = "https://github.com/login/oauth/access_token"
"#;
        let fc: FileConfig = toml::from_str(toml_str).expect("valid TOML with token_url");
        let servers = fc.servers.expect("servers present");
        let github = servers.get("github").expect("github server");
        let envs = github.environments.as_ref().expect("environments present");
        let prod = envs.get("prod").expect("prod environment");
        assert_eq!(
            prod.oauth_url.as_deref(),
            Some("https://github.com/login/device/code")
        );
        assert_eq!(
            prod.token_url.as_deref(),
            Some("https://github.com/login/oauth/access_token")
        );
    }

    #[test]
    fn parse_file_config_without_token_url() {
        let toml_str = r#"
[servers.legacy]
client_id = "legacy-client"

[servers.legacy.environments.prod]
default = true
oauth_url = "https://sso.example.com/device"
"#;
        let fc: FileConfig = toml::from_str(toml_str).expect("valid TOML without token_url");
        let servers = fc.servers.expect("servers present");
        let legacy = servers.get("legacy").expect("legacy server");
        let envs = legacy.environments.as_ref().expect("environments present");
        let prod = envs.get("prod").expect("prod environment");
        assert_eq!(
            prod.oauth_url.as_deref(),
            Some("https://sso.example.com/device")
        );
        assert!(
            prod.token_url.is_none(),
            "token_url should be None when not configured"
        );
    }

    #[test]
    fn env_var_overrides_token_url() {
        let _lock = TEST_ENV_MUTEX.lock().expect("env mutex poisoned");
        let _guard = isolated_env_guard();

        std::env::set_var("SSOJWT_TOKEN_URL", "https://custom.example.com/token");
        let cfg = Config::load().expect("Config::load should succeed");
        assert_eq!(
            cfg.token_url.as_deref(),
            Some("https://custom.example.com/token")
        );
    }

    #[test]
    fn token_url_absent_by_default() {
        let _lock = TEST_ENV_MUTEX.lock().expect("env mutex poisoned");
        let _guard = isolated_env_guard();

        let cfg = Config::load().expect("Config::load should succeed");
        assert!(
            cfg.token_url.is_none(),
            "token_url should be None by default"
        );
    }

    #[test]
    fn malformed_config_file_returns_error() {
        let _lock = TEST_ENV_MUTEX.lock().expect("env mutex poisoned");
        let _guard = isolated_env_guard();
        let path = Config::config_file_path();
        std::fs::create_dir_all(path.parent().expect("config parent")).expect("create parent");
        std::fs::write(&path, "not = [valid").expect("write invalid config");

        let err = Config::load().expect_err("invalid config should fail");
        assert!(err.to_string().contains("TOML"));
    }

    #[test]
    fn resolve_server_preserves_env_client_id_and_heartbeat() {
        let _lock = TEST_ENV_MUTEX.lock().expect("env mutex poisoned");
        let _guard = isolated_env_guard();

        let fc = FileConfig {
            default_server: Some("myco".into()),
            risk_level: None,
            biometric: None,
            cache_name: None,
            servers: Some(HashMap::from([(
                "myco".into(),
                ServerFileConfig {
                    client_id: Some("file-client".into()),
                    environments: Some(HashMap::from([(
                        "prod".into(),
                        EnvironmentFileConfig {
                            default: Some(true),
                            oauth_url: Some("https://auth.example.com/device".into()),
                            token_url: None,
                            heartbeat_url: Some("https://file.example.com/heartbeat".into()),
                        },
                    )])),
                },
            )])),
        };
        Config::save_file_config(&fc).expect("save config");

        std::env::set_var("SSOJWT_CLIENT_ID", "env-client");
        std::env::set_var("SSOJWT_HEARTBEAT_URL", "https://env.example.com/heartbeat");

        let mut cfg = Config::load().expect("load config");
        cfg.resolve_server().expect("resolve server");

        assert_eq!(cfg.client_id, "env-client");
        assert_eq!(
            cfg.heartbeat_url.as_deref(),
            Some("https://env.example.com/heartbeat")
        );
    }

    #[test]
    fn resolve_server_rejects_cleartext_environment_heartbeat_url() {
        let _lock = TEST_ENV_MUTEX.lock().expect("env mutex poisoned");
        let _guard = isolated_env_guard();

        let fc = FileConfig {
            default_server: Some("myco".into()),
            risk_level: None,
            biometric: None,
            cache_name: None,
            servers: Some(HashMap::from([(
                "myco".into(),
                ServerFileConfig {
                    client_id: Some("file-client".into()),
                    environments: Some(HashMap::from([(
                        "prod".into(),
                        EnvironmentFileConfig {
                            default: Some(true),
                            oauth_url: Some("https://auth.example.com/device".into()),
                            token_url: None,
                            heartbeat_url: Some("http://file.example.com/heartbeat".into()),
                        },
                    )])),
                },
            )])),
        };
        Config::save_file_config(&fc).expect("save config");

        let mut cfg = Config::load().expect("load config");
        let error = cfg
            .resolve_server()
            .expect_err("cleartext heartbeat_url should fail");
        assert!(error.to_string().contains("heartbeat_url must use HTTPS"));
    }
}
