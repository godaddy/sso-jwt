//! TPM 2.0 operations via Windows CNG.
//! This module is only compiled on Windows.

#![cfg(target_os = "windows")]

use anyhow::{anyhow, Result};
use windows::core::HSTRING;
use windows::Win32::Security::Cryptography::*;

const KEY_NAME: &str = "sso-jwt-cache-key";

/// Ensure the TPM key exists, creating it if necessary.
pub fn ensure_key(biometric: bool) -> Result<()> {
    unsafe {
        let mut provider = NCRYPT_PROV_HANDLE::default();
        NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0).map_err(|e| {
            anyhow!(
                "failed to open TPM provider: {e}. \
                 This machine may not have a TPM 2.0 module."
            )
        })?;

        let key_name = HSTRING::from(KEY_NAME);
        let mut key = NCRYPT_KEY_HANDLE::default();

        let opened = NCryptOpenKey(
            provider,
            &mut key,
            &key_name,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS::default(),
        );

        if opened.is_ok() {
            // Key exists
            NCryptFreeObject(key);
            NCryptFreeObject(provider);
            return Ok(());
        }

        // Create new key
        NCryptCreatePersistedKey(
            provider,
            &mut key,
            BCRYPT_ECDH_P256_ALGORITHM,
            &key_name,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS::default(),
        )
        .map_err(|e| anyhow!("failed to create TPM key: {e}"))?;

        if biometric {
            let policy = NCRYPT_UI_POLICY {
                dwVersion: 1,
                dwFlags: NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG,
                pszCreationTitle: windows::core::PCWSTR::null(),
                pszFriendlyName: windows::core::PCWSTR::null(),
                pszDescription: windows::core::PCWSTR::null(),
            };
            let _ = NCryptSetProperty(
                key,
                NCRYPT_UI_POLICY_PROPERTY,
                std::slice::from_raw_parts(
                    &policy as *const _ as *const u8,
                    size_of::<NCRYPT_UI_POLICY>(),
                ),
                NCRYPT_PERSIST_FLAG,
            );
        }

        NCryptFinalizeKey(key, NCRYPT_FLAGS::default())
            .map_err(|e| anyhow!("failed to finalize TPM key: {e}"))?;

        NCryptFreeObject(key);
        NCryptFreeObject(provider);
        Ok(())
    }
}

/// Encrypt data using the TPM-bound key.
pub fn encrypt(plaintext: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        let (provider, key) = open_key()?;

        let mut output_size: u32 = 0;
        NCryptEncrypt(
            key,
            Some(plaintext),
            None,
            None,
            &mut output_size,
            NCRYPT_PAD_PKCS1_FLAG,
        )
        .map_err(|e| anyhow!("encrypt size query: {e}"))?;

        let mut output = vec![0u8; output_size as usize];
        NCryptEncrypt(
            key,
            Some(plaintext),
            None,
            Some(&mut output),
            &mut output_size,
            NCRYPT_PAD_PKCS1_FLAG,
        )
        .map_err(|e| anyhow!("encrypt: {e}"))?;

        output.truncate(output_size as usize);

        NCryptFreeObject(key);
        NCryptFreeObject(provider);
        Ok(output)
    }
}

/// Decrypt data using the TPM-bound key.
pub fn decrypt(ciphertext: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        let (provider, key) = open_key()?;

        let mut output_size: u32 = 0;
        NCryptDecrypt(
            key,
            Some(ciphertext),
            None,
            None,
            &mut output_size,
            NCRYPT_PAD_PKCS1_FLAG,
        )
        .map_err(|e| anyhow!("decrypt size query: {e}"))?;

        let mut output = vec![0u8; output_size as usize];
        NCryptDecrypt(
            key,
            Some(ciphertext),
            None,
            Some(&mut output),
            &mut output_size,
            NCRYPT_PAD_PKCS1_FLAG,
        )
        .map_err(|e| anyhow!("decrypt: {e}"))?;

        output.truncate(output_size as usize);

        NCryptFreeObject(key);
        NCryptFreeObject(provider);
        Ok(output)
    }
}

/// Delete the TPM-bound key.
pub fn destroy() -> Result<()> {
    unsafe {
        let mut provider = NCRYPT_PROV_HANDLE::default();
        NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0)
            .map_err(|e| anyhow!("open provider: {e}"))?;

        let mut key = NCRYPT_KEY_HANDLE::default();
        let result = NCryptOpenKey(
            provider,
            &mut key,
            &HSTRING::from(KEY_NAME),
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS::default(),
        );

        if result.is_ok() {
            NCryptDeleteKey(key, 0).map_err(|e| anyhow!("delete key: {e}"))?;
        }

        NCryptFreeObject(provider);
        Ok(())
    }
}

unsafe fn open_key() -> Result<(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE)> {
    let mut provider = NCRYPT_PROV_HANDLE::default();
    NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0)
        .map_err(|e| anyhow!("open provider: {e}"))?;

    let mut key = NCRYPT_KEY_HANDLE::default();
    NCryptOpenKey(
        provider,
        &mut key,
        &HSTRING::from(KEY_NAME),
        CERT_KEY_SPEC(0),
        NCRYPT_FLAGS::default(),
    )
    .map_err(|e| {
        NCryptFreeObject(provider);
        anyhow!("open key: {e}. Run 'sso-jwt' once to create the key.")
    })?;

    Ok((provider, key))
}
