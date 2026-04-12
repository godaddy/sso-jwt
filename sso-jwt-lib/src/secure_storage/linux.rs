// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Software-only Linux storage backed by libenclaveapp's `SoftwareEncryptor`.
//!
//! Uses ECIES (P-256 ECDH + AES-256-GCM) with private keys stored on disk,
//! optionally encrypted by a keyring-stored KEK. This replaces the earlier
//! D-Bus keyring passthrough with a shared backend from libenclaveapp.

use anyhow::{anyhow, Result};
use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager};
use enclaveapp_core::types::{AccessPolicy, KeyType};
use enclaveapp_software::SoftwareEncryptor;
use zeroize::Zeroizing;

use super::SecureStorage;

/// Application name used to namespace keys in libenclaveapp.
const APP_NAME: &str = "sso-jwt";

/// Key label used for the credential encryption key.
const KEY_LABEL: &str = "cache-key";

/// Software-only Linux storage using libenclaveapp's `SoftwareEncryptor`.
///
/// Wraps `SoftwareEncryptor` with the same fixed key label used by the
/// macOS and Windows backends so the rest of sso-jwt is backend-agnostic.
pub struct KeyringStorage {
    encryptor: SoftwareEncryptor,
}

impl KeyringStorage {
    #[allow(clippy::print_stderr)]
    pub fn init(biometric: bool) -> Result<Self> {
        if biometric {
            eprintln!("warning: --biometric has no effect on Linux (no hardware security module)");
        }

        let encryptor = SoftwareEncryptor::new(APP_NAME);

        // Ensure the key exists; generate if missing.
        if encryptor.public_key(KEY_LABEL).is_err() {
            encryptor
                .generate(KEY_LABEL, KeyType::Encryption, AccessPolicy::None)
                .map_err(|e| anyhow!("failed to create software encryption key: {e}"))?;
        }

        Ok(Self { encryptor })
    }
}

impl SecureStorage for KeyringStorage {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encryptor
            .encrypt(KEY_LABEL, plaintext)
            .map_err(|e| anyhow!("software encryption failed: {e}"))
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let plaintext = self
            .encryptor
            .decrypt(KEY_LABEL, ciphertext)
            .map_err(|e| anyhow!("software decryption failed: {e}"))?;
        Ok(Zeroizing::new(plaintext))
    }

    fn destroy(&self) -> Result<()> {
        self.encryptor
            .delete_key(KEY_LABEL)
            .map_err(|e| anyhow!("failed to delete software encryption key: {e}"))
    }
}
