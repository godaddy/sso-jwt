use anyhow::Result;
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
    /// SSO environment
    #[arg(
        short,
        long,
        default_value = "prod",
        value_parser = ["dev", "test", "ote", "prod"]
    )]
    pub environment: String,

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
        _ => {}
    }

    // Load config and apply CLI overrides
    let mut config = Config::load()?;
    apply_cli_overrides(&mut config, &cli);

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

fn apply_cli_overrides(config: &mut Config, cli: &Cli) {
    config.environment = cli.environment.clone();
    config.cache_name = cli.cache_name.clone();
    config.risk_level = cli.risk_level;
    config.no_open = cli.no_open;
    config.clear = cli.clear;

    if cli.biometric {
        config.biometric = true;
    }
    if cli.oauth_url.is_some() {
        config.oauth_url.clone_from(&cli.oauth_url);
    }
}

fn resolve_token(config: &Config) -> Result<String> {
    let storage = secure_storage::platform_storage(config.biometric)?;
    cache::resolve_token(config, storage.as_ref())
}
