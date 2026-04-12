// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! WSL bridge storage using libenclaveapp's bridge client.
//!
//! Communicates with the Windows TPM bridge executable over JSON-RPC
//! (stdin/stdout). Uses `enclaveapp-bridge` for protocol types and
//! the client helper, with `enclaveapp-wsl` for WSL detection.

use anyhow::{anyhow, Result};
use std::path::PathBuf;
use zeroize::Zeroizing;

use super::SecureStorage;

/// Application name for bridge discovery and key namespacing.
const APP_NAME: &str = "sso-jwt";

/// Legacy paths for the bridge executable (from before libenclaveapp migration).
const LEGACY_BRIDGE_PATHS: &[&str] = &[
    "/mnt/c/Program Files/sso-jwt/sso-jwt-tpm-bridge.exe",
    "/mnt/c/ProgramData/sso-jwt/sso-jwt-tpm-bridge.exe",
];

/// Returns `true` if the current environment is Windows Subsystem for Linux.
pub fn is_wsl() -> bool {
    enclaveapp_wsl::is_wsl()
}

/// WSL TPM bridge client. Spawns the bridge executable on the Windows host
/// and communicates via stdin/stdout JSON-RPC using libenclaveapp's protocol.
pub struct WslTpmBridge {
    bridge_path: PathBuf,
    biometric: bool,
}

impl WslTpmBridge {
    pub fn init(biometric: bool) -> Result<Self> {
        let bridge_path =
            find_bridge_executable().ok_or_else(|| anyhow!("{}", bridge_not_found_message()))?;

        Ok(Self {
            bridge_path,
            biometric,
        })
    }
}

impl SecureStorage for WslTpmBridge {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        enclaveapp_bridge::bridge_encrypt(&self.bridge_path, APP_NAME, plaintext, self.biometric)
            .map_err(|e| anyhow!("TPM bridge encrypt failed: {e}"))
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let data = enclaveapp_bridge::bridge_decrypt(
            &self.bridge_path,
            APP_NAME,
            ciphertext,
            self.biometric,
        )
        .map_err(|e| anyhow!("TPM bridge decrypt failed: {e}"))?;
        Ok(Zeroizing::new(data))
    }

    fn destroy(&self) -> Result<()> {
        // The bridge does not expose a destroy method via libenclaveapp's client.
        // Key deletion is handled by the user removing keys on the Windows host.
        Ok(())
    }
}

/// Search for the bridge executable using enclaveapp-bridge's finder,
/// then fall back to legacy sso-jwt-specific paths.
fn find_bridge_executable() -> Option<PathBuf> {
    // Try the libenclaveapp standard discovery first.
    if let Some(path) = enclaveapp_bridge::find_bridge(APP_NAME) {
        return Some(path);
    }

    // Fall back to legacy sso-jwt-specific paths.
    for path_str in LEGACY_BRIDGE_PATHS {
        let path = std::path::Path::new(path_str);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }

    None
}

fn bridge_not_found_message() -> String {
    format!(
        "sso-jwt TPM bridge not found.\n\
         Install sso-jwt on the Windows host first, then re-run under WSL.\n\
         Expected paths:\n{}",
        LEGACY_BRIDGE_PATHS
            .iter()
            .map(|p| format!("  - {p}"))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wsl_detection_returns_bool() {
        // On a real Linux machine this returns true or false.
        // On macOS (where tests typically run) it should return false.
        let _ = is_wsl();
    }

    #[test]
    fn find_bridge_executable_does_not_panic() {
        // Should return None on most development machines.
        let _path = find_bridge_executable();
    }

    #[test]
    fn bridge_not_found_message_contains_paths() {
        let msg = bridge_not_found_message();
        assert!(msg.contains("sso-jwt TPM bridge not found"));
        for path in LEGACY_BRIDGE_PATHS {
            assert!(msg.contains(path));
        }
    }
}
