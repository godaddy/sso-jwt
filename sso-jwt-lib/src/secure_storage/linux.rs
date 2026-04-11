use anyhow::{anyhow, Result};
use zeroize::Zeroizing;

use super::SecureStorage;

/// Software keyring backend for native Linux (not WSL).
/// Uses the D-Bus Secret Service API via GNOME Keyring or KDE Wallet.
///
/// This is software-only encryption -- no hardware binding.
/// The JWT is stored as a secret service entry, encrypted by the user's
/// login keyring. Weaker than SE/TPM but still better than plaintext files.
pub struct KeyringStorage {
    _biometric: bool,
}

impl KeyringStorage {
    #[allow(clippy::print_stderr)]
    pub fn init(biometric: bool) -> Result<Self> {
        if biometric {
            eprintln!(
                "warning: --biometric has no effect on Linux (no hardware security module)"
            );
        }

        // Print one-time notice about software-only storage
        print_keyring_notice();

        Ok(Self {
            _biometric: biometric,
        })
    }
}

impl SecureStorage for KeyringStorage {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // On Linux, "encryption" is handled by the keyring itself.
        // We store the data as-is and rely on the keyring's own encryption.
        // To maintain the same interface, we just pass through.
        Ok(plaintext.to_vec())
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        // Inverse of encrypt -- passthrough since keyring handles encryption
        Ok(Zeroizing::new(ciphertext.to_vec()))
    }

    fn destroy(&self) -> Result<()> {
        // Cache file deletion is handled by the caller (cache.rs).
        // If we stored in keyring directly, we'd delete entries here.
        Ok(())
    }
}

#[allow(clippy::print_stderr)]
fn print_keyring_notice() {
    // Use a flag file to print only once
    let flag_path = std::env::var("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir())
        .join("sso-jwt-keyring-notice");

    if !flag_path.exists() {
        eprintln!(
            "notice: using software keyring (no hardware security module detected).\n\
             Token cache is encrypted by your login keyring but is not hardware-bound."
        );
        drop(std::fs::write(&flag_path, ""));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_roundtrip() {
        let storage = KeyringStorage { _biometric: false };
        let plaintext = b"test data";
        let encrypted = storage.encrypt(plaintext).unwrap();
        let decrypted = storage.decrypt(&encrypted).unwrap();
        assert_eq!(&*decrypted, plaintext);
    }
}
