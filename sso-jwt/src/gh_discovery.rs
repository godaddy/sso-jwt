// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Trusted discovery of the `gh` CLI binary.
//!
//! Resolving `gh` via `$PATH` lets a user-writable directory earlier on
//! the path shim the real binary — whatever \`gh\` is the first one on
//! PATH runs with the user's ambient GitHub credentials.  sso-jwt only
//! uses `gh` to fetch a server config (whose payload then goes through
//! HTTPS / `validate_endpoint_url`), so the blast radius is narrower
//! than signing-key tooling; still, there's no reason to trust any
//! random earlier-on-PATH binary.
//!
//! Search a short, fixed list of system package-manager install dirs
//! and the current executable's own dir. Only return a canonicalized
//! path that points at an actually-executable file.  If nothing is
//! found, callers fall back to their pre-existing "skip gh" path.

use std::path::{Path, PathBuf};

#[cfg(windows)]
use std::io::Read;

const GH_BIN_NAME: &str = if cfg!(windows) { "gh.exe" } else { "gh" };

pub fn find_trusted_gh() -> Option<PathBuf> {
    candidate_dirs()
        .into_iter()
        .map(|dir| dir.join(GH_BIN_NAME))
        .find_map(|candidate| resolve_trusted_binary_candidate(&candidate))
}

fn candidate_dirs() -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.to_path_buf());
        }
    }

    #[cfg(windows)]
    {
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
            candidates.push(local_app_data.join("Programs").join("gh").join("bin"));
            candidates.push(local_app_data.join("gh").join("bin"));
        }
        for var in ["ProgramFiles", "ProgramFiles(x86)"] {
            if let Some(pf) = std::env::var_os(var).map(PathBuf::from) {
                candidates.push(pf.join("GitHub CLI"));
                candidates.push(pf.join("gh").join("bin"));
            }
        }
    }

    #[cfg(not(windows))]
    {
        if let Some(home_dir) = dirs::home_dir() {
            candidates.push(home_dir.join(".local").join("bin"));
            candidates.push(home_dir.join(".cargo").join("bin"));
        }
        candidates.push(PathBuf::from("/opt/homebrew/bin"));
        candidates.push(PathBuf::from("/usr/local/bin"));
        candidates.push(PathBuf::from("/usr/bin"));
    }

    let mut unique: Vec<PathBuf> = Vec::new();
    for dir in candidates {
        if !unique.iter().any(|existing| existing == &dir) {
            unique.push(dir);
        }
    }
    unique
}

fn resolve_trusted_binary_candidate(path: &Path) -> Option<PathBuf> {
    let resolved = path.canonicalize().ok()?;
    if resolved.is_file() && candidate_looks_executable(&resolved) {
        Some(resolved)
    } else {
        None
    }
}

#[cfg(unix)]
fn candidate_looks_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(windows)]
fn candidate_looks_executable(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
        && has_pe_header(path)
}

#[cfg(windows)]
fn has_pe_header(path: &Path) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0_u8; 2];
    if file.read_exact(&mut magic).is_err() {
        return false;
    }
    magic == *b"MZ"
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn nonexistent_binary_returns_none() {
        let candidate = PathBuf::from("/definitely/not/a/real/gh-binary-abc123");
        assert!(resolve_trusted_binary_candidate(&candidate).is_none());
    }

    #[test]
    fn directory_is_not_an_executable() {
        let dir = tempfile::tempdir().unwrap();
        let candidate = dir.path().to_path_buf();
        assert!(resolve_trusted_binary_candidate(&candidate).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn non_executable_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gh");
        std::fs::write(&path, "#!/bin/sh\necho hi").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(resolve_trusted_binary_candidate(&path).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn executable_file_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gh");
        std::fs::write(&path, "#!/bin/sh\necho hi").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let resolved = resolve_trusted_binary_candidate(&path).unwrap();
        // canonicalize() resolves symlinks — the returned path should
        // exist and be a file.
        assert!(resolved.is_file());
    }
}
