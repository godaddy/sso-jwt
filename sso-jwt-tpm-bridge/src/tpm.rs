// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! TPM 2.0 storage operations via libenclaveapp.
//!
//! On Windows, this uses `enclaveapp-windows::TpmEncryptor` to perform
//! hardware-backed ECIES encryption via the Windows CNG/NCrypt APIs.
//!
//! On non-Windows platforms, all operations return an error at runtime.

#[cfg(target_os = "windows")]
mod platform {
    use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager};
    use enclaveapp_core::types::{AccessPolicy, KeyType};
    use enclaveapp_windows::TpmEncryptor;

    /// Application name for key namespacing.
    const APP_NAME: &str = "sso-jwt";

    /// Key label for the TPM bridge encryption key.
    const KEY_LABEL: &str = "cache-key";

    pub struct TpmStorage {
        encryptor: TpmEncryptor,
        #[allow(dead_code)]
        biometric: bool,
    }

    impl TpmStorage {
        pub fn new(biometric: bool) -> Result<Self, String> {
            let encryptor = TpmEncryptor::new(APP_NAME);

            if !encryptor.is_available() {
                return Err("TPM not available".to_string());
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
                    .map_err(|e| format!("key generation failed: {e}"))?;
            }

            Ok(Self {
                encryptor,
                biometric,
            })
        }

        pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
            self.encryptor
                .encrypt(KEY_LABEL, plaintext)
                .map_err(|e| e.to_string())
        }

        pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
            self.encryptor
                .decrypt(KEY_LABEL, ciphertext)
                .map_err(|e| e.to_string())
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod platform {
    pub struct TpmStorage {
        _biometric: bool,
    }

    impl TpmStorage {
        #[allow(clippy::unnecessary_wraps)]
        pub fn new(biometric: bool) -> Result<Self, String> {
            Ok(Self {
                _biometric: biometric,
            })
        }

        #[allow(clippy::unused_self)]
        pub fn encrypt(&self, _plaintext: &[u8]) -> Result<Vec<u8>, String> {
            Err("TPM bridge is only supported on Windows".to_string())
        }

        #[allow(clippy::unused_self)]
        pub fn decrypt(&self, _ciphertext: &[u8]) -> Result<Vec<u8>, String> {
            Err("TPM bridge is only supported on Windows".to_string())
        }
    }
}

pub use platform::TpmStorage;
