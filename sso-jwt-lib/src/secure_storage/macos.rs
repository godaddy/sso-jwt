// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! macOS Secure Enclave storage backed by libenclaveapp's CryptoKit ECIES.

use anyhow::{anyhow, Result};
use enclaveapp_apple::SecureEnclaveEncryptor;
use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager};
use enclaveapp_core::types::{AccessPolicy, KeyType};
use zeroize::Zeroizing;

use super::SecureStorage;

/// Application name used to namespace keys in libenclaveapp.
const APP_NAME: &str = "sso-jwt";

/// Key label used for the credential encryption key.
const KEY_LABEL: &str = "cache-key";

/// macOS Secure Enclave-backed storage using CryptoKit ECIES.
///
/// Wraps libenclaveapp's `SecureEnclaveEncryptor`, binding a fixed key label
/// so the rest of sso-jwt does not need to manage label selection.
pub struct SecureEnclaveStorage {
    encryptor: SecureEnclaveEncryptor,
}

impl SecureEnclaveStorage {
    pub fn init(biometric: bool) -> Result<Self> {
        let encryptor = SecureEnclaveEncryptor::new(APP_NAME);

        if !encryptor.is_available() {
            return Err(anyhow!(
                "Secure Enclave not available. \
                 Does this machine have a Secure Enclave (T2 chip or Apple Silicon)?"
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
                .map_err(|e| anyhow!("failed to create Secure Enclave key: {e}"))?;
        }

        Ok(Self { encryptor })
    }
}

impl SecureStorage for SecureEnclaveStorage {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encryptor
            .encrypt(KEY_LABEL, plaintext)
            .map_err(|e| anyhow!("Secure Enclave encryption failed: {e}"))
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let plaintext = self
            .encryptor
            .decrypt(KEY_LABEL, ciphertext)
            .map_err(|e| anyhow!("Secure Enclave decryption failed: {e}"))?;
        Ok(Zeroizing::new(plaintext))
    }

    fn destroy(&self) -> Result<()> {
        self.encryptor
            .delete_key(KEY_LABEL)
            .map_err(|e| anyhow!("failed to delete Secure Enclave key: {e}"))
    }
}
