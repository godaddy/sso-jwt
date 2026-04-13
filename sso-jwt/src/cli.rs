use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use sso_jwt_lib::{cache, config::Config, secure_storage};

use crate::exec;
use crate::shell_init;

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

        /// GitHub repo path: owner/repo/file.toml (fetches via GitHub API)
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

    // Load config, apply CLI overrides, and resolve server profile
    let mut config = Config::load()?;
    apply_cli_overrides(&mut config, &cli);

    // Handle --clear before resolve_server() so it works even with no server configured.
    if config.clear && cli.command.is_none() {
        if config.resolve_server().is_ok() {
            cache::clear(&config)?;
            eprintln!("Cache cleared.");
        } else {
            eprintln!("No server configured. Nothing to clear.");
        }
        return Ok(());
    }

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

    let (toml_content, display_source) = if is_github {
        let content = fetch_from_github(source)?;
        (content, format!("github:{source}"))
    } else if source.starts_with("http://") || source.starts_with("https://") {
        let resp = reqwest::blocking::get(source)?;
        if !resp.status().is_success() {
            bail!(
                "failed to fetch server config from {source}: HTTP {}",
                resp.status()
            );
        }
        (resp.text()?, source.to_string())
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
/// 1. Raw GitHub URL (fast, no auth, works for public repos)
/// 2. `git archive` over SSH (most users have SSH keys)
/// 3. `gh` CLI via `gh api` (handles SAML SSO, internal repos, PATs)
fn fetch_from_github(github_path: &str) -> Result<String> {
    let parts: Vec<&str> = github_path.splitn(3, '/').collect();
    if parts.len() < 3 {
        bail!("--from-github format: owner/repo/path (e.g. myorg/sso-jwt-config/server.toml)");
    }
    let (owner, repo, path) = (parts[0], parts[1], parts[2]);

    // Strategy 1: Raw GitHub URL (fast, no auth needed for public repos)
    let raw_url = format!("https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{path}");
    if let Ok(resp) = reqwest::blocking::get(&raw_url) {
        if resp.status().is_success() {
            if let Ok(text) = resp.text() {
                return Ok(text);
            }
        }
    }

    // Strategy 2: git archive over SSH -- most users have SSH keys configured
    let shell_cmd = format!(
        "git archive --remote=git@github.com:{owner}/{repo}.git HEAD {path} | tar -xO {path}"
    );
    if let Ok(output) = std::process::Command::new("sh")
        .args(["-c", &shell_cmd])
        .stderr(std::process::Stdio::null())
        .output()
    {
        if output.status.success() {
            let content = String::from_utf8_lossy(&output.stdout).to_string();
            if !content.is_empty() {
                return Ok(content);
            }
        }
    }

    // Strategy 3: gh CLI -- handles SAML SSO, internal repos
    if let Ok(output) = std::process::Command::new("gh")
        .args([
            "api",
            &format!("repos/{owner}/{repo}/contents/{path}"),
            "-H",
            "Accept: application/vnd.github.raw+json",
        ])
        .stderr(std::process::Stdio::null())
        .output()
    {
        if output.status.success() {
            let content = String::from_utf8_lossy(&output.stdout).to_string();
            if !content.is_empty() {
                return Ok(content);
            }
        }
    }

    bail!(
        "failed to fetch {owner}/{repo}/{path} from GitHub.\n\
         Tried: gh CLI, GitHub API, raw URL, git archive.\n\
         Make sure you have access to the repo (try: gh auth login)"
    )
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
    let storage = secure_storage::platform_storage(config.biometric)?;
    cache::resolve_token(config, storage.as_ref())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use clap::Parser;

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
}
