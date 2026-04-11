use anyhow::{bail, Result};
use serde::Deserialize;
use std::path::PathBuf;

const DEFAULT_ENVIRONMENT: &str = "prod";
const DEFAULT_RISK_LEVEL: u8 = 2;
const DEFAULT_CACHE_NAME: &str = "default";
const DEFAULT_ENV_VAR: &str = "COMPANY_JWT";

/// Resolved configuration after merging file, env vars, and CLI flags.
#[derive(Debug, Clone)]
pub struct Config {
    pub environment: String,
    pub risk_level: u8,
    pub biometric: bool,
    pub cache_name: String,
    pub env_var: String,
    pub oauth_url: Option<String>,
    pub no_open: bool,
    pub clear: bool,
}

/// On-disk TOML configuration (all fields optional).
#[derive(Debug, Deserialize, Default)]
struct FileConfig {
    environment: Option<String>,
    risk_level: Option<u8>,
    biometric: Option<bool>,
    cache_name: Option<String>,
    env_var: Option<String>,
}

impl Config {
    /// Load config from file and environment variables.
    /// CLI flags are applied separately by the caller.
    pub fn load() -> Result<Self> {
        let fc = Self::load_file_config().unwrap_or_default();

        let mut cfg = Config {
            environment: fc
                .environment
                .unwrap_or_else(|| DEFAULT_ENVIRONMENT.to_string()),
            risk_level: fc.risk_level.unwrap_or(DEFAULT_RISK_LEVEL),
            biometric: fc.biometric.unwrap_or(false),
            cache_name: fc
                .cache_name
                .unwrap_or_else(|| DEFAULT_CACHE_NAME.to_string()),
            env_var: fc
                .env_var
                .unwrap_or_else(|| DEFAULT_ENV_VAR.to_string()),
            oauth_url: None,
            no_open: false,
            clear: false,
        };

        // Environment variables override file config
        if let Ok(v) = std::env::var("SSOJWT_ENVIRONMENT") {
            cfg.environment = v;
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
        if let Ok(v) = std::env::var("SSOJWT_ENV_VAR") {
            cfg.env_var = v;
        }
        if let Ok(v) = std::env::var("SSOJWT_OAUTH_URL") {
            cfg.oauth_url = Some(v);
        }

        Ok(cfg)
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
        let sanitized: String = self
            .cache_name
            .replace(['/', '\\'], "")
            .replace("..", "");
        let name = if sanitized.is_empty() {
            "default"
        } else {
            &sanitized
        };
        Self::cache_dir().join(format!("{name}.enc"))
    }

    /// Resolve the OAuth service URL for the configured environment.
    pub fn oauth_url(&self) -> Result<String> {
        if let Some(ref url) = self.oauth_url {
            return Ok(url.clone());
        }
        match self.environment.as_str() {
            "dev" => Ok("https://auth.dev.example.com".to_string()),
            "test" => Ok("https://auth.test.example.com".to_string()),
            "ote" => Ok("https://auth.ote.example.com".to_string()),
            "prod" => Ok("https://auth.example.com".to_string()),
            other => bail!("unknown environment: {other}"),
        }
    }

    /// Resolve the SSO service URL for heartbeat validation.
    pub fn sso_url(&self) -> String {
        match self.environment.as_str() {
            "dev" => "https://sso.dev.example.com".to_string(),
            "test" => "https://sso.test.example.com".to_string(),
            "ote" => "https://sso.ote.example.com".to_string(),
            _ => "https://sso.example.com".to_string(),
        }
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

    const SSOJWT_KEYS: [&str; 6] = [
        "SSOJWT_ENVIRONMENT",
        "SSOJWT_RISK_LEVEL",
        "SSOJWT_BIOMETRIC",
        "SSOJWT_CACHE_NAME",
        "SSOJWT_ENV_VAR",
        "SSOJWT_OAUTH_URL",
    ];

    /// Save current SSOJWT env vars, clear them, and return saved values.
    fn save_and_clear_env() -> Vec<Option<String>> {
        let saved: Vec<_> =
            SSOJWT_KEYS.iter().map(|k| std::env::var(k).ok()).collect();
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

    #[test]
    fn default_values() {
        let _lock = ENV_MUTEX.lock().expect("env mutex poisoned");
        let saved = save_and_clear_env();

        let cfg = Config::load().expect("Config::load should succeed");
        assert_eq!(cfg.environment, "prod");
        assert_eq!(cfg.risk_level, 2);
        assert!(!cfg.biometric);
        assert_eq!(cfg.cache_name, "default");
        assert_eq!(cfg.env_var, "COMPANY_JWT");
        assert!(cfg.oauth_url.is_none());

        restore_env(saved);
    }

    #[test]
    fn oauth_url_prod() {
        let mut cfg = Config::load().unwrap();
        cfg.environment = "prod".to_string();
        cfg.oauth_url = None;
        assert_eq!(cfg.oauth_url().unwrap(), "https://auth.example.com");
    }

    #[test]
    fn oauth_url_dev() {
        let mut cfg = Config::load().unwrap();
        cfg.environment = "dev".to_string();
        cfg.oauth_url = None;
        assert_eq!(
            cfg.oauth_url().unwrap(),
            "https://auth.dev.example.com"
        );
    }

    #[test]
    fn oauth_url_custom_override() {
        let mut cfg = Config::load().unwrap();
        cfg.oauth_url = Some("https://custom.example.com".to_string());
        assert_eq!(cfg.oauth_url().unwrap(), "https://custom.example.com");
    }

    #[test]
    fn oauth_url_unknown_env() {
        let mut cfg = Config::load().unwrap();
        cfg.environment = "invalid".to_string();
        cfg.oauth_url = None;
        assert!(cfg.oauth_url().is_err());
    }

    #[test]
    fn sso_url_mapping() {
        let mut cfg = Config::load().unwrap();
        cfg.environment = "dev".to_string();
        assert_eq!(cfg.sso_url(), "https://sso.dev.example.com");
        cfg.environment = "test".to_string();
        assert_eq!(cfg.sso_url(), "https://sso.test.example.com");
        cfg.environment = "ote".to_string();
        assert_eq!(cfg.sso_url(), "https://sso.ote.example.com");
        cfg.environment = "prod".to_string();
        assert_eq!(cfg.sso_url(), "https://sso.example.com");
        cfg.environment = "unknown".to_string();
        assert_eq!(cfg.sso_url(), "https://sso.example.com"); // defaults to prod
    }

    #[test]
    fn cache_file_path_uses_cache_name() {
        let mut cfg = Config::load().unwrap();
        cfg.cache_name = "myenv".to_string();
        let path = cfg.cache_file_path();
        assert!(path.to_string_lossy().ends_with("myenv.enc"));
    }

    #[test]
    fn parse_file_config_full() {
        let toml_str = r#"
environment = "dev"
risk_level = 3
biometric = true
cache_name = "work"
env_var = "MY_JWT"
"#;
        let fc: FileConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(fc.environment.as_deref(), Some("dev"));
        assert_eq!(fc.risk_level, Some(3));
        assert_eq!(fc.biometric, Some(true));
        assert_eq!(fc.cache_name.as_deref(), Some("work"));
        assert_eq!(fc.env_var.as_deref(), Some("MY_JWT"));
    }

    #[test]
    fn parse_file_config_empty() {
        let fc: FileConfig = toml::from_str("").unwrap();
        assert!(fc.environment.is_none());
        assert!(fc.risk_level.is_none());
    }

    #[test]
    fn parse_file_config_partial() {
        let toml_str = r#"risk_level = 1"#;
        let fc: FileConfig = toml::from_str(toml_str).unwrap();
        assert!(fc.environment.is_none());
        assert_eq!(fc.risk_level, Some(1));
    }

    #[test]
    fn env_var_overrides_environment() {
        let _lock = ENV_MUTEX.lock().expect("env mutex poisoned");
        let saved = save_and_clear_env();

        std::env::set_var("SSOJWT_ENVIRONMENT", "ote");
        let cfg = Config::load().expect("Config::load should succeed");
        assert_eq!(cfg.environment, "ote");

        restore_env(saved);
    }

    #[test]
    fn env_var_biometric_values() {
        let _lock = ENV_MUTEX.lock().expect("env mutex poisoned");
        let saved = save_and_clear_env();

        // "true" enables biometric
        std::env::set_var("SSOJWT_BIOMETRIC", "true");
        let cfg = Config::load().expect("Config::load should succeed");
        assert!(cfg.biometric, "SSOJWT_BIOMETRIC=true should enable biometric");

        // "1" enables biometric
        std::env::set_var("SSOJWT_BIOMETRIC", "1");
        let cfg = Config::load().expect("Config::load should succeed");
        assert!(cfg.biometric, "SSOJWT_BIOMETRIC=1 should enable biometric");

        // "false" disables biometric
        std::env::set_var("SSOJWT_BIOMETRIC", "false");
        let cfg = Config::load().expect("Config::load should succeed");
        assert!(!cfg.biometric, "SSOJWT_BIOMETRIC=false should disable biometric");

        restore_env(saved);
    }

    #[test]
    fn unknown_toml_keys_ignored() {
        let toml_str = r#"
environment = "dev"
risk_level = 1
unknown_key = "should be ignored"
another_unknown = 42
"#;
        let fc: FileConfig =
            toml::from_str(toml_str).expect("unknown keys should be silently ignored");
        assert_eq!(fc.environment.as_deref(), Some("dev"));
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
    fn oauth_url_all_environments() {
        let mut cfg = Config {
            environment: String::new(),
            risk_level: DEFAULT_RISK_LEVEL,
            biometric: false,
            cache_name: DEFAULT_CACHE_NAME.to_string(),
            env_var: DEFAULT_ENV_VAR.to_string(),
            oauth_url: None,
            no_open: false,
            clear: false,
        };

        cfg.environment = "dev".to_string();
        assert_eq!(
            cfg.oauth_url().expect("dev oauth_url"),
            "https://auth.dev.example.com"
        );

        cfg.environment = "test".to_string();
        assert_eq!(
            cfg.oauth_url().expect("test oauth_url"),
            "https://auth.test.example.com"
        );

        cfg.environment = "ote".to_string();
        assert_eq!(
            cfg.oauth_url().expect("ote oauth_url"),
            "https://auth.ote.example.com"
        );

        cfg.environment = "prod".to_string();
        assert_eq!(
            cfg.oauth_url().expect("prod oauth_url"),
            "https://auth.example.com"
        );
    }

    #[test]
    fn oauth_url_custom_ignores_environment() {
        let cfg = Config {
            environment: "dev".to_string(),
            risk_level: DEFAULT_RISK_LEVEL,
            biometric: false,
            cache_name: DEFAULT_CACHE_NAME.to_string(),
            env_var: DEFAULT_ENV_VAR.to_string(),
            oauth_url: Some("https://my-custom.example.com".to_string()),
            no_open: false,
            clear: false,
        };
        // Even though environment is "dev", custom URL takes precedence
        assert_eq!(
            cfg.oauth_url().expect("custom oauth_url"),
            "https://my-custom.example.com"
        );
    }

    #[test]
    fn cache_name_path_traversal_stripped() {
        let mut cfg = Config {
            environment: DEFAULT_ENVIRONMENT.to_string(),
            risk_level: DEFAULT_RISK_LEVEL,
            biometric: false,
            cache_name: "../../etc/passwd".to_string(),
            env_var: DEFAULT_ENV_VAR.to_string(),
            oauth_url: None,
            no_open: false,
            clear: false,
        };
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
        assert!(filename.ends_with(".enc"), "should still end in .enc: {filename}");

        // Pure traversal with nothing left should fall back to "default"
        cfg.cache_name = "../..".to_string();
        let path = cfg.cache_file_path();
        let filename = path
            .file_name()
            .expect("should have filename")
            .to_string_lossy();
        assert_eq!(filename, "default.enc");
    }

    #[test]
    fn cache_name_backslash_stripped() {
        let cfg = Config {
            environment: DEFAULT_ENVIRONMENT.to_string(),
            risk_level: DEFAULT_RISK_LEVEL,
            biometric: false,
            cache_name: r"..\..\windows\system32".to_string(),
            env_var: DEFAULT_ENV_VAR.to_string(),
            oauth_url: None,
            no_open: false,
            clear: false,
        };
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
        let cfg = Config {
            environment: DEFAULT_ENVIRONMENT.to_string(),
            risk_level: DEFAULT_RISK_LEVEL,
            biometric: false,
            cache_name: "my-project".to_string(),
            env_var: DEFAULT_ENV_VAR.to_string(),
            oauth_url: None,
            no_open: false,
            clear: false,
        };
        let path = cfg.cache_file_path();
        let filename = path
            .file_name()
            .expect("should have filename")
            .to_string_lossy();
        assert_eq!(filename, "my-project.enc");
    }
}
