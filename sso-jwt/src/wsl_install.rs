//! WSL integration for the Windows installer.
//!
//! When `sso-jwt install` runs on Windows, it detects installed WSL
//! distributions and installs the Linux binary + shell integration into each.
//! When `sso-jwt uninstall` runs, it removes them.

#![cfg(target_os = "windows")]

use anyhow::{anyhow, Result};
use enclaveapp_wsl::install::WslInstallConfig;

fn make_config() -> Result<WslInstallConfig> {
    // Find the Linux binary bundled alongside the Windows binary.
    let linux_binary = find_linux_binary()?;

    Ok(WslInstallConfig {
        app_name: "sso-jwt".to_string(),
        shell_block: r#"# Add sso-jwt to PATH and enable export detection
if [ -d "$HOME/.local/bin" ]; then
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *) export PATH="$HOME/.local/bin:$PATH" ;;
    esac
fi
if command -v sso-jwt >/dev/null 2>&1; then
    eval "$(sso-jwt shell-init)"
fi"#
        .to_string(),
        linux_binary_path: Some(linux_binary),
        linux_binary_target: Some(".local/bin/sso-jwt".to_string()),
        auto_install_linux_release: None,
    })
}

/// Install sso-jwt into all detected WSL distributions.
pub fn install_into_wsl_distros() -> Result<()> {
    let config = make_config()?;
    let results = enclaveapp_wsl::install::configure_all_distros(&config);

    if results.is_empty() {
        println!("No WSL distributions detected.");
        return Ok(());
    }

    println!("Detected {} WSL distribution(s):", results.len());

    for result in &results {
        println!("  Configuring {}...", result.distro_name);
        match &result.outcome {
            Ok(actions) => {
                for action in actions {
                    println!("    {action}");
                }
            }
            Err(e) => {
                eprintln!("    warning: {e}");
            }
        }
    }

    Ok(())
}

/// Remove sso-jwt from all detected WSL distributions.
pub fn uninstall_from_wsl_distros() -> Result<()> {
    let config = make_config()?;
    let results = enclaveapp_wsl::install::unconfigure_all_distros(&config);

    for result in &results {
        println!("  Cleaning {}...", result.distro_name);
        match &result.outcome {
            Ok(actions) => {
                for action in actions {
                    println!("    {action}");
                }
            }
            Err(e) => {
                eprintln!(
                    "    warning: could not clean WSL distro {}: {e}",
                    result.distro_name
                );
            }
        }
    }
    Ok(())
}

/// Find the Linux sso-jwt binary bundled with the Windows install.
fn find_linux_binary() -> Result<std::path::PathBuf> {
    let exe_dir = std::env::current_exe()?
        .parent()
        .ok_or_else(|| anyhow!("exe has no parent directory"))?
        .to_path_buf();

    let linux_bin = exe_dir.join("sso-jwt-linux");
    if linux_bin.exists() {
        return Ok(linux_bin);
    }

    for name in &["sso-jwt-linux-amd64", "sso-jwt-linux-arm64"] {
        let path = exe_dir.join(name);
        if path.exists() {
            return Ok(path);
        }
    }

    Err(anyhow!(
        "Linux binary not found in install directory.\n\
         Expected: {}\n\
         The MSI installer should bundle the Linux binary.",
        linux_bin.display()
    ))
}
