use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use enclaveapp_app_storage::{create_encryption_storage, AccessPolicy, StorageConfig};
use sso_jwt_lib::{cache, config::Config};
use std::io::Read;
use std::process::Stdio;
use std::time::Duration;

use crate::exec;
use crate::shell_init;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SERVER_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Parser)]
#[command(
    name = "sso-jwt",
    version,
    about = "Obtain SSO JWTs with hardware-backed secure caching"
)]
pub struct Cli {
    /// Server profile to use
    #[arg(short, long)]
    pub server: Option<String>,

    /// Server environment
    #[arg(short, long)]
    pub environment: Option<String>,

    /// Cache name (allows multiple concurrent caches)
    #[arg(short, long, default_value = "default")]
    pub cache_name: String,

    /// Token risk level (1=low/24h, 2=medium/12h, 3=high/1h)
    #[arg(
        short,
        long,
        default_value_t = 2,
        value_parser = clap::value_parser!(u8).range(1..=3)
    )]
    pub risk_level: u8,

    /// Override OAuth service URL
    #[arg(long)]
    pub oauth_url: Option<String>,

    /// Require biometric (Touch ID / Windows Hello) for each use
    #[arg(long)]
    pub biometric: bool,

    /// Don't auto-open browser for authentication
    #[arg(long)]
    pub no_open: bool,

    /// Clear cached token and exit
    #[arg(long)]
    pub clear: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Print shell integration script for export detection
    ShellInit {
        /// Shell type (auto-detected if omitted, or pass "auto")
        #[arg(value_parser = ["bash", "zsh", "fish", "auto"])]
        shell: Option<String>,
    },

    /// Run a command with the JWT injected into its environment
    Exec {
        /// Environment variable name for the JWT
        #[arg(long, default_value = "SSO_JWT")]
        env_var: String,

        /// Command and arguments to run
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    /// Install sso-jwt (configure shell integration; on Windows, also install into WSL distros)
    Install,

    /// Uninstall sso-jwt configuration (on Windows, also remove from WSL distros)
    Uninstall,

    /// Add a server profile from a URL, GitHub repo, or local file
    AddServer {
        /// Label for this server profile (defaults to "default")
        label: Option<String>,

        /// URL or local path to fetch the server configuration from
        #[arg(long, group = "source")]
        from_url: Option<String>,

        /// GitHub repo path pinned to a ref: owner/repo@ref/file.toml
        #[arg(long, group = "source")]
        from_github: Option<String>,

        /// Overwrite existing server with the same label
        #[arg(long)]
        force: bool,
    },
}

#[allow(clippy::print_stdout, clippy::print_stderr)]
pub fn run(cli: Cli) -> Result<()> {
    // Handle subcommands that don't need config
    match &cli.command {
        Some(Commands::ShellInit { shell }) => {
            let detected = shell_init::detect_shell();
            let shell_name = match shell.as_deref() {
                Some("auto") | None => &detected,
                Some(s) => s,
            };
            print!("{}", shell_init::generate(shell_name));
            return Ok(());
        }
        Some(Commands::Install) => {
            return run_install();
        }
        Some(Commands::Uninstall) => {
            return run_uninstall();
        }
        Some(Commands::AddServer {
            ref label,
            ref from_url,
            ref from_github,
            force,
        }) => {
            let set_default = label.is_none();
            let label = label.as_deref().unwrap_or("default");
            let source = from_url.as_deref().or(from_github.as_deref());
            let is_github = from_github.is_some();
            return run_add_server(label, source, is_github, set_default, *force);
        }
        _ => {}
    }

    // Handle --clear before full config resolution. Cache deletion only depends on
    // local naming inputs, so it should still work when the server profile is gone,
    // the config file is malformed, or the server config is temporarily invalid.
    if cli.clear && cli.command.is_none() {
        let mut config = Config::load_for_clear();
        apply_cli_overrides(&mut config, &cli);
        cache::clear(&config)?;
        cache::purge_deprecated_legacy_cache_files()?;
        eprintln!("Cache cleared.");
        return Ok(());
    }

    // Load config, apply CLI overrides, and resolve server profile
    let mut config = Config::load()?;
    apply_cli_overrides(&mut config, &cli);

    config.resolve_server()?;

    match cli.command {
        Some(Commands::Exec {
            ref env_var,
            ref command,
        }) => {
            let jwt = resolve_token(&config)?;
            exec::run(env_var, &jwt, command)
        }
        None => {
            let jwt = resolve_token(&config)?;
            print!("{jwt}");
            Ok(())
        }
        _ => unreachable!(),
    }
}

#[allow(clippy::print_stdout, clippy::print_stderr)]
fn run_install() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        eprintln!("Installing sso-jwt...");
        crate::wsl_install::install_into_wsl_distros()?;
        eprintln!("Done.");
    }

    #[cfg(not(target_os = "windows"))]
    {
        let shell = shell_init::detect_shell();
        let rc_file = match shell.as_str() {
            "zsh" => "~/.zshrc",
            "fish" => "~/.config/fish/config.fish",
            _ => "~/.bashrc",
        };
        eprintln!("Add to {rc_file}:");
        eprintln!();
        if shell == "fish" {
            eprintln!("  sso-jwt shell-init fish | source");
        } else {
            eprintln!("  eval \"$(sso-jwt shell-init)\"");
        }
        eprintln!();
    }

    Ok(())
}

#[allow(clippy::print_stderr)]
fn run_uninstall() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        eprintln!("Uninstalling sso-jwt...");
        crate::wsl_install::uninstall_from_wsl_distros()?;
        eprintln!("Done.");
    }

    #[cfg(not(target_os = "windows"))]
    {
        eprintln!("Remove the sso-jwt shell-init line from your shell profile.");
    }

    Ok(())
}

#[allow(clippy::print_stderr)]
fn run_add_server(
    label: &str,
    source: Option<&str>,
    is_github: bool,
    set_default: bool,
    force: bool,
) -> Result<()> {
    let source = source.ok_or_else(|| anyhow::anyhow!("specify --from-url or --from-github"))?;
    let client = blocking_http_client()?;

    let (toml_content, display_source) = if is_github {
        let content = fetch_from_github(source, &client)?;
        (content, format!("github:{source}"))
    } else if source.starts_with("http://") {
        bail!("refusing to fetch server config over cleartext HTTP: {source}");
    } else if source.starts_with("https://") {
        (fetch_url_text(&client, source)?, source.to_string())
    } else {
        (std::fs::read_to_string(source)?, source.to_string())
    };

    Config::add_server_from_toml(label, &toml_content, set_default, force)?;

    eprintln!("Added server '{label}' from {display_source}");
    if set_default {
        eprintln!("Set '{label}' as the default server.");
    }
    Ok(())
}

/// Fetch a file from GitHub using multiple strategies, in order:
/// 1. Raw GitHub URL using an explicit pinned ref
/// 2. `gh` CLI via `gh api` (handles SAML SSO, internal repos, PATs)
fn fetch_from_github(github_path: &str, client: &reqwest::blocking::Client) -> Result<String> {
    let source = GitHubSource::parse(github_path)?;

    // Strategy 1: Raw GitHub URL (fast, no auth needed for public repos)
    let raw_url = format!(
        "https://raw.githubusercontent.com/{}/{}/{}/{}",
        source.owner, source.repo, source.r#ref, source.path
    );
    if let Ok(text) = fetch_url_text(client, &raw_url) {
        return Ok(text);
    }

    // Strategy 2: gh CLI -- handles SAML SSO, internal repos
    if let Some(content) = fetch_from_github_via_gh(&source)? {
        return Ok(content);
    }

    bail!(
        "failed to fetch {github_path} from GitHub.\n\
         Tried: gh CLI and raw.githubusercontent.com using ref '{}'.\n\
         Make sure you have access to the repo (try: gh auth login)",
        source.r#ref
    )
}

fn blocking_http_client() -> Result<reqwest::blocking::Client> {
    blocking_http_client_with_timeout(HTTP_TIMEOUT)
}

fn blocking_http_client_with_timeout(timeout: Duration) -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()?)
}

fn read_text_with_limit<R: Read>(mut reader: R, source: &str) -> Result<String> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(MAX_SERVER_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SERVER_CONFIG_BYTES {
        bail!(
            "server config from {source} exceeds {} bytes",
            MAX_SERVER_CONFIG_BYTES
        );
    }
    String::from_utf8(bytes).map_err(Into::into)
}

fn read_child_stdout_with_limit(
    child: &mut std::process::Child,
    source: &str,
    timeout: Duration,
) -> Result<String> {
    use std::sync::mpsc;
    use std::thread;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("gh output missing stdout"))?;
    let source = source.to_string();
    let reader_source = source.clone();
    let (tx, rx) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        drop(tx.send(read_text_with_limit(stdout, &reader_source)));
    });

    let content = match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            drop(child.kill());
            drop(child.wait());
            drop(reader.join());
            bail!("gh CLI timed out fetching server config from {source}");
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            drop(child.wait());
            drop(reader.join());
            bail!("gh CLI output reader disconnected unexpectedly");
        }
    }?;

    reader
        .join()
        .map_err(|_| anyhow::anyhow!("gh CLI output reader panicked"))?;
    Ok(content)
}

fn fetch_from_github_via_gh(source: &GitHubSource) -> Result<Option<String>> {
    let display_source = format!(
        "github:{}/{}@{}/{}",
        source.owner, source.repo, source.r#ref, source.path
    );
    let mut child = match std::process::Command::new("gh")
        .args([
            "api",
            &format!(
                "repos/{}/{}/contents/{}",
                source.owner, source.repo, source.path
            ),
            "-H",
            "Accept: application/vnd.github.raw+json",
            "-F",
            &format!("ref={}", source.r#ref),
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .env("GH_PROMPT_DISABLED", "1")
        .env("GH_NO_UPDATE_NOTIFIER", "1")
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return Ok(None),
    };

    let content = read_child_stdout_with_limit(&mut child, &display_source, HTTP_TIMEOUT)?;
    let status = child.wait()?;
    if status.success() && !content.is_empty() {
        Ok(Some(content))
    } else {
        Ok(None)
    }
}

fn fetch_url_text(client: &reqwest::blocking::Client, source: &str) -> Result<String> {
    let resp = client.get(source).send()?;
    if !resp.status().is_success() {
        bail!(
            "failed to fetch server config from {source}: HTTP {}",
            resp.status()
        );
    }
    if let Some(length) = resp.content_length() {
        if length > MAX_SERVER_CONFIG_BYTES {
            bail!(
                "server config from {source} exceeds {} bytes",
                MAX_SERVER_CONFIG_BYTES
            );
        }
    }
    read_text_with_limit(resp, source)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GitHubSource {
    owner: String,
    repo: String,
    r#ref: String,
    path: String,
}

impl GitHubSource {
    fn parse(input: &str) -> Result<Self> {
        let parts: Vec<&str> = input.splitn(3, '/').collect();
        if parts.len() < 3 {
            bail!(
                "--from-github format: owner/repo@ref/path (e.g. myorg/configs@v1.2.3/server.toml)"
            );
        }

        let owner = parts[0];
        let repo_and_ref = parts[1];
        let path = parts[2];

        let (repo, r#ref) = repo_and_ref.split_once('@').ok_or_else(|| {
            anyhow::anyhow!(
                "--from-github requires a pinned ref: owner/repo@ref/path (for example @v1.2.3 or @<commit>)"
            )
        })?;

        if owner.is_empty() || repo.is_empty() || r#ref.is_empty() || path.is_empty() {
            bail!(
                "--from-github format: owner/repo@ref/path (e.g. myorg/configs@v1.2.3/server.toml)"
            );
        }

        Ok(Self {
            owner: owner.to_string(),
            repo: repo.to_string(),
            r#ref: r#ref.to_string(),
            path: path.to_string(),
        })
    }
}

fn apply_cli_overrides(config: &mut Config, cli: &Cli) {
    if let Some(ref s) = cli.server {
        config.server = s.clone();
    }
    if let Some(ref e) = cli.environment {
        config.environment = Some(e.clone());
    }
    if let Some(ref u) = cli.oauth_url {
        config.oauth_url = u.clone();
    }
    config.cache_name = cli.cache_name.clone();
    config.risk_level = cli.risk_level;
    config.no_open = cli.no_open;
    config.clear = cli.clear;
    if cli.biometric {
        config.biometric = true;
    }
}

fn resolve_token(config: &Config) -> Result<String> {
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
    })?;
    cache::resolve_token(config, storage.as_ref())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;
    use std::thread;

    static SCRIPT_COUNTER: AtomicU64 = AtomicU64::new(0);
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[cfg(unix)]
    fn temp_script(name: &str, body: &str) -> PathBuf {
        let id = SCRIPT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "sso-jwt-cli-test-{}-{}-{}",
            std::process::id(),
            id,
            name
        ));
        fs::write(&path, body).unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).unwrap();
        path
    }

    #[cfg(windows)]
    fn temp_script(name: &str, body: &str) -> PathBuf {
        let id = SCRIPT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let base = std::env::temp_dir().join(format!(
            "sso-jwt-cli-test-{}-{}-{}",
            std::process::id(),
            id,
            name
        ));
        let script_path = base.with_extension("ps1");
        let wrapper_path = base.with_extension("cmd");
        fs::write(&script_path, body).unwrap();
        let wrapper = format!(
            "@echo off\r\npowershell -NoProfile -ExecutionPolicy Bypass -File \"{}\"\r\n",
            script_path.display()
        );
        fs::write(&wrapper_path, wrapper).unwrap();
        wrapper_path
    }

    fn cleanup_script(path: &Path) {
        drop(fs::remove_file(path));
        #[cfg(windows)]
        {
            drop(fs::remove_file(path.with_extension("ps1")));
        }
    }

    fn default_cli() -> Cli {
        Cli {
            server: None,
            environment: None,
            cache_name: "default".to_string(),
            risk_level: 2,
            oauth_url: None,
            biometric: false,
            no_open: false,
            clear: false,
            command: None,
        }
    }

    fn default_config() -> Config {
        Config {
            server: "default".to_string(),
            environment: None,
            oauth_url: String::new(),
            token_url: None,
            heartbeat_url: None,
            client_id: "sso-jwt".to_string(),
            risk_level: 2,
            biometric: false,
            cache_name: "default".to_string(),
            no_open: false,
            clear: false,
        }
    }

    struct TestEnvGuard {
        prev_xdg: Option<std::ffi::OsString>,
        prev_home: Option<std::ffi::OsString>,
    }

    struct TestConfigDir {
        path: PathBuf,
    }

    impl TestConfigDir {
        fn new(name: &str) -> Self {
            let id = SCRIPT_COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!(
                "sso-jwt-cli-config-{}-{}-{name}",
                std::process::id(),
                id
            ));
            drop(fs::remove_dir_all(&path));
            fs::create_dir_all(&path).expect("create temp config dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestConfigDir {
        fn drop(&mut self) {
            drop(fs::remove_dir_all(&self.path));
        }
    }

    impl Drop for TestEnvGuard {
        fn drop(&mut self) {
            match self.prev_xdg.take() {
                Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
            match self.prev_home.take() {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    fn isolate_config_dir(dir: &TestConfigDir) -> TestEnvGuard {
        let prev_xdg = std::env::var_os("XDG_CONFIG_HOME");
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("XDG_CONFIG_HOME", dir.path());
        std::env::set_var("HOME", dir.path());
        TestEnvGuard {
            prev_xdg,
            prev_home,
        }
    }

    #[test]
    fn apply_overrides_server() {
        let mut config = default_config();
        let cli = Cli {
            server: Some("custom-server".to_string()),
            ..default_cli()
        };
        apply_cli_overrides(&mut config, &cli);
        assert_eq!(config.server, "custom-server");
    }

    #[test]
    fn apply_overrides_environment() {
        let mut config = default_config();
        let cli = Cli {
            environment: Some("staging".to_string()),
            ..default_cli()
        };
        apply_cli_overrides(&mut config, &cli);
        assert_eq!(config.environment.as_deref(), Some("staging"));
    }

    #[test]
    fn apply_overrides_oauth_url() {
        let mut config = default_config();
        let cli = Cli {
            oauth_url: Some("https://auth.example.com/device".to_string()),
            ..default_cli()
        };
        apply_cli_overrides(&mut config, &cli);
        assert_eq!(config.oauth_url, "https://auth.example.com/device");
    }

    #[test]
    fn apply_overrides_risk_level() {
        let mut config = default_config();
        let cli = Cli {
            risk_level: 3,
            ..default_cli()
        };
        apply_cli_overrides(&mut config, &cli);
        assert_eq!(config.risk_level, 3);
    }

    #[test]
    fn apply_overrides_cache_name() {
        let mut config = default_config();
        let cli = Cli {
            cache_name: "my-cache".to_string(),
            ..default_cli()
        };
        apply_cli_overrides(&mut config, &cli);
        assert_eq!(config.cache_name, "my-cache");
    }

    #[test]
    fn apply_overrides_biometric_true() {
        let mut config = default_config();
        let cli = Cli {
            biometric: true,
            ..default_cli()
        };
        apply_cli_overrides(&mut config, &cli);
        assert!(config.biometric);
    }

    #[test]
    fn apply_overrides_biometric_false_does_not_override_config() {
        let mut config = default_config();
        config.biometric = true;
        let cli = Cli {
            biometric: false,
            ..default_cli()
        };
        apply_cli_overrides(&mut config, &cli);
        // biometric: false in CLI should NOT override config's true
        assert!(config.biometric);
    }

    #[test]
    fn apply_overrides_no_open() {
        let mut config = default_config();
        let cli = Cli {
            no_open: true,
            ..default_cli()
        };
        apply_cli_overrides(&mut config, &cli);
        assert!(config.no_open);
    }

    #[test]
    fn apply_overrides_clear() {
        let mut config = default_config();
        let cli = Cli {
            clear: true,
            ..default_cli()
        };
        apply_cli_overrides(&mut config, &cli);
        assert!(config.clear);
    }

    #[test]
    fn apply_overrides_preserves_defaults() {
        let mut config = default_config();
        config.server = "original".to_string();
        config.oauth_url = "https://original.com".to_string();
        let cli = default_cli();
        apply_cli_overrides(&mut config, &cli);
        // server and oauth_url should remain unchanged when CLI values are None/empty
        assert_eq!(config.server, "original");
        assert_eq!(config.oauth_url, "https://original.com");
    }

    #[test]
    fn apply_overrides_all_fields() {
        let mut config = default_config();
        let cli = Cli {
            server: Some("s".to_string()),
            environment: Some("e".to_string()),
            cache_name: "c".to_string(),
            risk_level: 1,
            oauth_url: Some("https://oauth.example.com".to_string()),
            biometric: true,
            no_open: true,
            clear: true,
            command: None,
        };
        apply_cli_overrides(&mut config, &cli);
        assert_eq!(config.server, "s");
        assert_eq!(config.environment.as_deref(), Some("e"));
        assert_eq!(config.cache_name, "c");
        assert_eq!(config.risk_level, 1);
        assert_eq!(config.oauth_url, "https://oauth.example.com");
        assert!(config.biometric);
        assert!(config.no_open);
        assert!(config.clear);
    }

    #[test]
    fn parse_cli_help() {
        let result = Cli::try_parse_from(["sso-jwt", "--help"]);
        // --help causes an error (exit code 0), but clap returns Err
        assert!(result.is_err());
    }

    #[test]
    fn parse_cli_shell_init_bash() {
        let cli = Cli::parse_from(["sso-jwt", "shell-init", "bash"]);
        match cli.command {
            Some(Commands::ShellInit { shell }) => {
                assert_eq!(shell.as_deref(), Some("bash"));
            }
            _ => unreachable!("expected ShellInit command"),
        }
    }

    #[test]
    fn parse_cli_exec() {
        let cli = Cli::parse_from(["sso-jwt", "exec", "--", "my-command", "arg1"]);
        match cli.command {
            Some(Commands::Exec { env_var, command }) => {
                assert_eq!(env_var, "SSO_JWT");
                assert_eq!(command, vec!["my-command", "arg1"]);
            }
            _ => unreachable!("expected Exec command"),
        }
    }

    #[test]
    fn parse_cli_exec_custom_env_var() {
        let cli = Cli::parse_from(["sso-jwt", "exec", "--env-var", "MY_TOKEN", "--", "cmd"]);
        match cli.command {
            Some(Commands::Exec { env_var, .. }) => {
                assert_eq!(env_var, "MY_TOKEN");
            }
            _ => unreachable!("expected Exec command"),
        }
    }

    #[test]
    fn parse_cli_flags() {
        let cli = Cli::parse_from([
            "sso-jwt",
            "--server",
            "myco",
            "--environment",
            "prod",
            "--risk-level",
            "3",
            "--cache-name",
            "work",
            "--biometric",
            "--no-open",
            "--clear",
        ]);
        assert_eq!(cli.server.as_deref(), Some("myco"));
        assert_eq!(cli.environment.as_deref(), Some("prod"));
        assert_eq!(cli.risk_level, 3);
        assert_eq!(cli.cache_name, "work");
        assert!(cli.biometric);
        assert!(cli.no_open);
        assert!(cli.clear);
    }

    #[test]
    fn parse_cli_defaults() {
        let cli = Cli::parse_from(["sso-jwt"]);
        assert!(cli.server.is_none());
        assert!(cli.environment.is_none());
        assert_eq!(cli.cache_name, "default");
        assert_eq!(cli.risk_level, 2);
        assert!(!cli.biometric);
        assert!(!cli.no_open);
        assert!(!cli.clear);
        assert!(cli.command.is_none());
    }

    #[test]
    fn parse_cli_install() {
        let cli = Cli::parse_from(["sso-jwt", "install"]);
        assert!(matches!(cli.command, Some(Commands::Install)));
    }

    #[test]
    fn parse_cli_uninstall() {
        let cli = Cli::parse_from(["sso-jwt", "uninstall"]);
        assert!(matches!(cli.command, Some(Commands::Uninstall)));
    }

    #[test]
    fn parse_cli_add_server_with_label() {
        let cli = Cli::parse_from([
            "sso-jwt",
            "add-server",
            "myco",
            "--from-url",
            "https://example.com/config.toml",
            "--force",
        ]);
        match cli.command {
            Some(Commands::AddServer {
                label,
                from_url,
                from_github,
                force,
            }) => {
                assert_eq!(label.as_deref(), Some("myco"));
                assert_eq!(from_url.as_deref(), Some("https://example.com/config.toml"));
                assert!(from_github.is_none());
                assert!(force);
            }
            _ => unreachable!("expected AddServer command"),
        }
    }

    #[test]
    fn parse_cli_add_server_no_label() {
        let cli = Cli::parse_from([
            "sso-jwt",
            "add-server",
            "--from-url",
            "https://example.com/config.toml",
        ]);
        match cli.command {
            Some(Commands::AddServer { label, .. }) => {
                assert!(label.is_none(), "label should be None when omitted");
            }
            _ => unreachable!("expected AddServer command"),
        }
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn run_install_non_windows_does_not_error() {
        // On non-Windows, run_install just prints instructions
        let result = run_install();
        assert!(result.is_ok());
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn run_uninstall_non_windows_does_not_error() {
        let result = run_uninstall();
        assert!(result.is_ok());
    }

    #[test]
    fn run_add_server_no_source_returns_error() {
        let result = run_add_server("label", None, false, false, false);
        assert!(result.is_err());
        let err = result.expect_err("should error").to_string();
        assert!(
            err.contains("--from-url") || err.contains("--from-github"),
            "expected source error, got: {err}"
        );
    }

    #[test]
    fn github_source_requires_pinned_ref() {
        let err = GitHubSource::parse("owner/repo/path.toml").unwrap_err();
        assert!(err.to_string().contains("pinned ref"));
    }

    #[test]
    fn github_source_parses_owner_repo_ref_and_path() {
        let source = GitHubSource::parse("owner/repo@v1.2.3/path/to/server.toml").unwrap();
        assert_eq!(source.owner, "owner");
        assert_eq!(source.repo, "repo");
        assert_eq!(source.r#ref, "v1.2.3");
        assert_eq!(source.path, "path/to/server.toml");
    }

    #[test]
    fn run_add_server_rejects_cleartext_http() {
        let err = run_add_server(
            "label",
            Some("http://example.com/config.toml"),
            false,
            false,
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("cleartext HTTP"));
    }

    #[test]
    fn run_clear_succeeds_without_resolving_server() {
        let _lock = ENV_MUTEX.lock().expect("env mutex poisoned");
        let dir = TestConfigDir::new("clear");
        let _guard = isolate_config_dir(&dir);

        let config = Config {
            server: "clear-test".to_string(),
            environment: Some("prod".to_string()),
            oauth_url: String::new(),
            token_url: None,
            heartbeat_url: None,
            client_id: "sso-jwt".to_string(),
            risk_level: 2,
            biometric: false,
            cache_name: "cache-main".to_string(),
            no_open: false,
            clear: false,
        };

        let primary = config.cache_file_path();
        let legacy = Config::cache_dir().join("clear-test-prod-cache-main.enc");
        fs::create_dir_all(primary.parent().expect("cache parent")).expect("mkdir");
        fs::write(&primary, b"primary").expect("write primary");
        fs::write(&legacy, b"legacy").expect("write legacy");

        run(Cli {
            server: Some("clear-test".to_string()),
            environment: Some("prod".to_string()),
            cache_name: "cache-main".to_string(),
            risk_level: 2,
            oauth_url: None,
            biometric: false,
            no_open: false,
            clear: true,
            command: None,
        })
        .expect("clear should succeed without server resolution");

        assert!(!primary.exists());
        assert!(!legacy.exists());
    }

    #[test]
    fn run_clear_ignores_malformed_config_and_purges_deprecated_legacy_caches() {
        let _lock = ENV_MUTEX.lock().expect("env mutex poisoned");
        let dir = TestConfigDir::new("clear-malformed-config");
        let _guard = isolate_config_dir(&dir);
        fs::create_dir_all(Config::config_dir()).expect("mkdir config dir");
        fs::write(Config::config_file_path(), "not = [valid").expect("write malformed config");

        let config = Config {
            server: "clear-test".to_string(),
            environment: Some("prod".to_string()),
            oauth_url: String::new(),
            token_url: None,
            heartbeat_url: None,
            client_id: "sso-jwt".to_string(),
            risk_level: 2,
            biometric: false,
            cache_name: "cache-main".to_string(),
            no_open: false,
            clear: false,
        };
        let primary = config.cache_file_path();
        let legacy = Config::cache_dir().join("clear-test-prod-cache-main.enc");
        fs::create_dir_all(primary.parent().expect("cache parent")).expect("mkdir");
        fs::write(&primary, b"primary").expect("write primary");
        fs::write(&legacy, b"legacy").expect("write legacy");

        run(Cli {
            server: Some("clear-test".to_string()),
            environment: Some("prod".to_string()),
            cache_name: "cache-main".to_string(),
            risk_level: 2,
            oauth_url: None,
            biometric: false,
            no_open: false,
            clear: true,
            command: None,
        })
        .expect("clear should ignore malformed config");

        assert!(!primary.exists());
        assert!(!legacy.exists());
    }

    #[test]
    fn fetch_url_text_times_out_for_stalled_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0_u8; 1024];
                drop(stream.read(&mut request));
                thread::sleep(Duration::from_millis(200));
                drop(stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world",
                ));
            }
        });

        let client = blocking_http_client_with_timeout(Duration::from_millis(50)).unwrap();
        let error = fetch_url_text(&client, &format!("http://{addr}/config.toml")).unwrap_err();
        let message = format!("{error:#}").to_ascii_lowercase();

        server.join().unwrap();
        assert!(
            message.contains("timed out") || message.contains("timeout"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn fetch_url_text_rejects_oversized_response() {
        let oversized = "x".repeat((MAX_SERVER_CONFIG_BYTES as usize) + 1);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0_u8; 1024];
                drop(stream.read(&mut request));
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    oversized.len(),
                    oversized
                );
                drop(stream.write_all(response.as_bytes()));
            }
        });

        let client = blocking_http_client().unwrap();
        let error = fetch_url_text(&client, &format!("http://{addr}/config.toml")).unwrap_err();
        assert!(error.to_string().contains("exceeds"));
        server.join().unwrap();
    }

    #[test]
    fn read_child_stdout_with_limit_times_out_for_stalled_process() {
        #[cfg(unix)]
        let script = temp_script(
            "stalled-gh.sh",
            r#"#!/bin/sh
sleep 1
printf 'too late'
"#,
        );
        #[cfg(windows)]
        let script = temp_script(
            "stalled-gh",
            r#"Start-Sleep -Seconds 1
[Console]::Out.Write('too late')
"#,
        );

        let mut child = std::process::Command::new(&script)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let error = read_child_stdout_with_limit(
            &mut child,
            "github:owner/repo@ref/file.toml",
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        cleanup_script(&script);
    }
}
