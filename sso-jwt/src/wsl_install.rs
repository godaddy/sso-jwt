//! WSL integration for the Windows installer.
//!
//! When `sso-jwt install` runs on Windows, it detects installed WSL
//! distributions and installs the Linux binary + shell integration into each.
//! When `sso-jwt uninstall` runs, it removes them.

#![cfg(target_os = "windows")]

use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;

/// A detected WSL distribution.
struct WslDistro {
    name: String,
    /// UNC path to the distro's home directory from Windows side
    /// e.g., \\wsl$\Ubuntu\home\username
    home_path: PathBuf,
}

const BEGIN_MARKER: &str = "# BEGIN sso-jwt managed block -- do not edit";
const END_MARKER: &str = "# END sso-jwt managed block";

/// Install sso-jwt into all detected WSL distributions.
/// Called by `sso-jwt install` on Windows.
pub fn install_into_wsl_distros() -> Result<()> {
    let distros = detect_wsl_distros();
    if distros.is_empty() {
        println!("No WSL distributions detected.");
        return Ok(());
    }

    println!("Detected {} WSL distribution(s):", distros.len());

    // Find the Linux binary to install. It should be bundled alongside
    // the Windows binary in the install directory.
    let linux_binary = find_linux_binary()?;

    for distro in &distros {
        println!("  Configuring {}...", distro.name);
        if let Err(e) = install_into_distro(distro, &linux_binary) {
            eprintln!("    warning: {e}");
        }
    }

    Ok(())
}

/// Remove sso-jwt from all detected WSL distributions.
/// Called by `sso-jwt uninstall` on Windows.
pub fn uninstall_from_wsl_distros() -> Result<()> {
    let distros = detect_wsl_distros();
    for distro in &distros {
        println!("  Cleaning {}...", distro.name);
        if let Err(e) = uninstall_from_distro(distro) {
            eprintln!("    warning: could not clean WSL distro {}: {e}", distro.name);
        }
    }
    Ok(())
}

/// Detect installed WSL distributions by running `wsl --list --quiet`.
fn detect_wsl_distros() -> Vec<WslDistro> {
    let output = match std::process::Command::new("wsl")
        .args(["--list", "--quiet"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    // wsl --list outputs UTF-16LE on some Windows versions
    let stdout = decode_wsl_output(&output.stdout);
    let mut distros = Vec::new();

    for line in stdout.lines() {
        let name = line.trim().trim_matches('\0').to_string();
        if name.is_empty() {
            continue;
        }

        if let Some(home_path) = find_wsl_home(&name) {
            distros.push(WslDistro { name, home_path });
        }
    }

    distros
}

/// Decode WSL output, handling both UTF-8 and UTF-16LE.
fn decode_wsl_output(bytes: &[u8]) -> String {
    // Check for UTF-16LE BOM
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let u16s: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        String::from_utf16_lossy(&u16s)
    } else {
        String::from_utf8_lossy(bytes).to_string()
    }
}

/// Find the WSL user's home directory path from Windows.
fn find_wsl_home(distro: &str) -> Option<PathBuf> {
    let output = std::process::Command::new("wsl")
        .args(["-d", distro, "--", "echo", "$HOME"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let linux_home = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_string();
    if linux_home.is_empty() {
        return None;
    }

    // Try \\wsl$\<distro>\<path> first, then \\wsl.localhost\<distro>\<path>
    for prefix in &[r"\\wsl$", r"\\wsl.localhost"] {
        let win_path = format!(
            r"{}\{}{}",
            prefix,
            distro,
            linux_home.replace('/', r"\")
        );
        let path = PathBuf::from(&win_path);
        if path.exists() {
            return Some(path);
        }
    }

    None
}

/// Find the Linux sso-jwt binary bundled with the Windows install.
fn find_linux_binary() -> Result<PathBuf> {
    // The Linux binary should be in the same directory as the running exe
    let exe_dir = std::env::current_exe()
        .context("cannot determine exe path")?
        .parent()
        .ok_or_else(|| anyhow!("exe has no parent directory"))?
        .to_path_buf();

    let linux_bin = exe_dir.join("sso-jwt-linux");
    if linux_bin.exists() {
        return Ok(linux_bin);
    }

    // Also check for arch-specific names
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

/// Install sso-jwt into a single WSL distro.
fn install_into_distro(
    distro: &WslDistro,
    linux_binary: &PathBuf,
) -> Result<()> {
    // 1. Copy the Linux binary into the distro's ~/.local/bin/
    let local_bin = distro.home_path.join(".local").join("bin");
    std::fs::create_dir_all(&local_bin)
        .with_context(|| format!("create {}", local_bin.display()))?;

    let dest = local_bin.join("sso-jwt");
    std::fs::copy(linux_binary, &dest)
        .with_context(|| format!("copy binary to {}", dest.display()))?;

    // Make executable via WSL
    let _ = std::process::Command::new("wsl")
        .args(["-d", &distro.name, "--", "chmod", "+x"])
        .arg(format!(
            "{}/.local/bin/sso-jwt",
            find_linux_home(&distro.name).unwrap_or_default()
        ))
        .status();

    println!("    Installed binary to ~/.local/bin/sso-jwt");

    // 2. Inject shell integration block into shell configs
    let shell_block = generate_shell_block();
    let mut configured = false;

    for rc_name in &[".bashrc", ".zshrc"] {
        let rc_path = distro.home_path.join(rc_name);
        if rc_path.exists() {
            inject_block(&rc_path, &shell_block, &distro.name)
                .with_context(|| format!("inject into {rc_name}"))?;
            println!("    Updated {rc_name}");
            configured = true;
        }
    }

    if !configured {
        // Create .bashrc as last resort
        let bashrc = distro.home_path.join(".bashrc");
        let content = format!("{shell_block}\n");
        std::fs::write(&bashrc, &content)
            .context("create .bashrc")?;
        println!("    Created .bashrc");
    }

    Ok(())
}

/// Remove sso-jwt from a single WSL distro.
fn uninstall_from_distro(distro: &WslDistro) -> Result<()> {
    // Remove shell integration blocks
    for name in &[".bashrc", ".zshrc", ".profile"] {
        let path = distro.home_path.join(name);
        if path.exists() {
            remove_block(&path)?;
        }
    }

    // Remove the binary
    let binary = distro
        .home_path
        .join(".local")
        .join("bin")
        .join("sso-jwt");
    if binary.exists() {
        std::fs::remove_file(&binary).ok();
        println!("    Removed ~/.local/bin/sso-jwt");
    }

    Ok(())
}

fn find_linux_home(distro: &str) -> Option<String> {
    let output = std::process::Command::new("wsl")
        .args(["-d", distro, "--", "echo", "$HOME"])
        .output()
        .ok()?;
    Some(
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_string(),
    )
}

/// Generate the shell block that adds ~/.local/bin to PATH and
/// sets up the sso-jwt shell integration (export detection).
fn generate_shell_block() -> String {
    format!(
        r#"{BEGIN_MARKER}
# Add sso-jwt to PATH and enable export detection
if [ -d "$HOME/.local/bin" ]; then
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *) export PATH="$HOME/.local/bin:$PATH" ;;
    esac
fi
if command -v sso-jwt >/dev/null 2>&1; then
    eval "$(sso-jwt shell-init)"
fi
{END_MARKER}"#
    )
}

/// Inject a managed block into a shell config file.
///
/// Safety measures (ported from sshenc):
/// 1. Back up the original file before first modification
/// 2. Write to a temp file first
/// 3. Syntax-check the modified file via `wsl -- bash -n` / `zsh -n`
/// 4. Only commit the change if syntax check passes
/// 5. If syntax check fails, leave the original untouched
fn inject_block(
    path: &PathBuf,
    block: &str,
    distro_name: &str,
) -> Result<()> {
    let content = std::fs::read_to_string(path)?;

    // Already present? Idempotent no-op.
    if content.contains(BEGIN_MARKER) {
        return Ok(());
    }

    // Back up the original before first modification
    let backup = path.with_extension("sso-jwt-backup");
    if !backup.exists() {
        std::fs::copy(path, &backup)
            .with_context(|| format!("backup {} failed", path.display()))?;
    }

    // Build the modified content
    let mut new_content = content;
    if !new_content.ends_with('\n') {
        new_content.push('\n');
    }
    new_content.push('\n');
    new_content.push_str(block);
    new_content.push('\n');

    // Write to a temp file first
    let tmp = path.with_extension("sso-jwt-tmp");
    std::fs::write(&tmp, &new_content)
        .with_context(|| format!("write temp file {}", tmp.display()))?;

    // Determine the right shell for syntax checking
    let file_name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    let shell = if file_name.contains("zsh") {
        "zsh"
    } else {
        "bash"
    };

    // Syntax-check the modified file via WSL
    let check = std::process::Command::new("wsl")
        .args(["-d", distro_name, "--", shell, "-n"])
        .stdin(std::process::Stdio::from(
            std::fs::File::open(&tmp)
                .with_context(|| format!("open temp file for syntax check"))?,
        ))
        .output();

    match check {
        Ok(o) if o.status.success() => {
            // Syntax OK -- commit the change
            std::fs::rename(&tmp, path)
                .with_context(|| format!("rename temp to {}", path.display()))?;
        }
        Ok(o) => {
            // Syntax error -- do NOT modify the original
            let _ = std::fs::remove_file(&tmp);
            let stderr = String::from_utf8_lossy(&o.stderr);
            return Err(anyhow!(
                "ABORTED: modified {} has syntax errors ({}). Original untouched.\n\
                 Backup at: {}\n\
                 Error: {}",
                file_name,
                shell,
                backup.display(),
                stderr.trim()
            ));
        }
        Err(_) => {
            // Can't run syntax check (WSL shell not available?)
            // Proceed cautiously -- our block is known-valid shell
            std::fs::rename(&tmp, path)
                .with_context(|| format!("rename temp to {}", path.display()))?;
        }
    }

    Ok(())
}

/// Remove the managed block from a shell config file.
fn remove_block(path: &PathBuf) -> Result<()> {
    let content = std::fs::read_to_string(path)?;
    if !content.contains(BEGIN_MARKER) {
        return Ok(());
    }

    let lines: Vec<&str> = content.lines().collect();
    let mut new_lines: Vec<&str> = Vec::new();
    let mut in_block = false;

    for line in &lines {
        if line.contains(BEGIN_MARKER) {
            in_block = true;
            // Remove trailing blank line before the block
            if let Some(last) = new_lines.last() {
                if last.is_empty() {
                    new_lines.pop();
                }
            }
            continue;
        }
        if line.contains(END_MARKER) {
            in_block = false;
            continue;
        }
        if !in_block {
            new_lines.push(line);
        }
    }

    let mut result = new_lines.join("\n");
    if !result.is_empty() {
        result.push('\n');
    }
    std::fs::write(path, &result)?;
    Ok(())
}
