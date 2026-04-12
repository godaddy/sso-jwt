// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Windows TPM 2.0 storage backed by libenclaveapp's CNG encryptor.

use anyhow::{anyhow, Result};
use zeroize::Zeroizing;

use super::SecureStorage;

/// Application name used to namespace keys in libenclaveapp.
const APP_NAME: &str = "sso-jwt";

/// Key label used for the credential encryption key.
const KEY_LABEL: &str = "cache-key";

/// TPM 2.0 storage backend for Windows.
/// Uses libenclaveapp's `TpmEncryptor` for hardware-backed ECIES encryption.
pub struct TpmStorage {
    #[cfg(target_os = "windows")]
    encryptor: enclaveapp_windows::TpmEncryptor,
    #[cfg(not(target_os = "windows"))]
    _biometric: bool,
}

impl TpmStorage {
    pub fn init(biometric: bool) -> Result<Self> {
        #[cfg(not(target_os = "windows"))]
        {
            let _ = biometric;
            anyhow::bail!("TPM storage is only available on Windows");
        }

        #[cfg(target_os = "windows")]
        {
            use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager};
            use enclaveapp_core::types::{AccessPolicy, KeyType};

            let encryptor = enclaveapp_windows::TpmEncryptor::new(APP_NAME);

            if !encryptor.is_available() {
                return Err(anyhow!(
                    "TPM not available. This machine may not have a TPM 2.0 module."
                ));
            }

            // Ensure the key exists; generate if missing.
            if encryptor.public_key(KEY_LABEL).is_err() {
                let policy = if biometric {
                    AccessPolicy::BiometricOnly
                } else {
                    AccessPolicy::None
                };
                encryptor
                    .generate(KEY_LABEL, KeyType::Encryption, policy)
                    .map_err(|e| anyhow!("failed to create TPM key: {e}"))?;
            }

            Ok(Self { encryptor })
        }
    }
}

impl SecureStorage for TpmStorage {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        #[cfg(not(target_os = "windows"))]
        {
            let _ = plaintext;
            anyhow::bail!("TPM storage is only available on Windows");
        }

        #[cfg(target_os = "windows")]
        {
            use enclaveapp_core::traits::EnclaveEncryptor;
            self.encryptor
                .encrypt(KEY_LABEL, plaintext)
                .map_err(|e| anyhow!("TPM encryption failed: {e}"))
        }
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        #[cfg(not(target_os = "windows"))]
        {
            let _ = ciphertext;
            anyhow::bail!("TPM storage is only available on Windows");
        }

        #[cfg(target_os = "windows")]
        {
            use enclaveapp_core::traits::EnclaveEncryptor;
            let plaintext = self
                .encryptor
                .decrypt(KEY_LABEL, ciphertext)
                .map_err(|e| anyhow!("TPM decryption failed: {e}"))?;
            Ok(Zeroizing::new(plaintext))
        }
    }

    fn destroy(&self) -> Result<()> {
        #[cfg(not(target_os = "windows"))]
        {
            anyhow::bail!("TPM storage is only available on Windows");
        }

        #[cfg(target_os = "windows")]
        {
            use enclaveapp_core::traits::EnclaveKeyManager;
            self.encryptor
                .delete_key(KEY_LABEL)
                .map_err(|e| anyhow!("failed to delete TPM key: {e}"))
        }
    }
}
