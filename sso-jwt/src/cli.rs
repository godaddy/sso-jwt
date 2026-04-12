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
        /// Shell type (auto-detected if omitted)
        #[arg(value_parser = ["bash", "zsh", "fish"])]
        shell: Option<String>,
    },

    /// Run a command with the JWT injected into its environment
    Exec {
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
        /// Label for this server profile
        label: String,

        /// URL or local path to fetch the server configuration from
        #[arg(long, group = "source")]
        from_url: Option<String>,

        /// GitHub repo path: owner/repo/file.toml (fetches via GitHub API)
        #[arg(long, group = "source")]
        from_github: Option<String>,

        /// Set this server as the default
        #[arg(long)]
        default: bool,

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
            let shell_name = shell.as_deref().unwrap_or(&detected);
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
            default: set_default,
            force,
        }) => {
            let source = from_url.as_deref().or(from_github.as_deref());
            let is_github = from_github.is_some();
            return run_add_server(label, source, is_github, *set_default, *force);
        }
        _ => {}
    }

    // Load config, apply CLI overrides, and resolve server profile
    let mut config = Config::load()?;
    apply_cli_overrides(&mut config, &cli);
    config.resolve_server()?;

    match cli.command {
        Some(Commands::Exec { ref command }) => {
            let jwt = resolve_token(&config)?;
            exec::run(&config.env_var, &jwt, command)
        }
        None => {
            if config.clear {
                cache::clear(&config)?;
                eprintln!("Cache cleared.");
                return Ok(());
            }

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
/// 3. `gh` CLI (handles SAML SSO, internal repos, PATs)
/// 4. GitHub API with `gh auth token` (direct HTTP)
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

    // Strategy 3: GitHub API with gh auth token
    let gh_token = std::process::Command::new("gh")
        .args(["auth", "token"])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

    if let Some(ref token) = gh_token {
        let api_url = format!("https://api.github.com/repos/{owner}/{repo}/contents/{path}");
        let client = reqwest::blocking::Client::new();
        if let Ok(resp) = client
            .get(&api_url)
            .header("Accept", "application/vnd.github.raw+json")
            .header("User-Agent", "sso-jwt")
            .header("Authorization", format!("Bearer {token}"))
            .send()
        {
            if resp.status().is_success() {
                if let Ok(text) = resp.text() {
                    return Ok(text);
                }
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
