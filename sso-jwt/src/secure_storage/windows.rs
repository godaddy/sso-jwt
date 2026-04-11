use anyhow::{anyhow, Result};
use zeroize::Zeroizing;

use super::SecureStorage;

/// TPM 2.0 storage backend for Windows.
/// Uses CNG (Cryptography Next Generation) via the Microsoft Platform Crypto Provider.
pub struct TpmStorage {
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
            Self::init_windows(biometric)
        }
    }

    #[cfg(target_os = "windows")]
    fn init_windows(biometric: bool) -> Result<Self> {
        use windows::Win32::Security::Cryptography::*;
        use windows::core::*;

        // Open the Microsoft Platform Crypto Provider (TPM)
        let mut provider = NCRYPT_PROV_HANDLE::default();
        unsafe {
            let status = NCryptOpenStorageProvider(
                &mut provider,
                MS_PLATFORM_CRYPTO_PROVIDER,
                0,
            );
            if status.is_err() {
                return Err(anyhow!(
                    "failed to open TPM provider: {status:?}. \
                     This machine may not have a TPM 2.0 module."
                ));
            }
        }

        // Try to open existing key, create if not found
        let mut key = NCRYPT_KEY_HANDLE::default();
        let key_name: HSTRING = HSTRING::from("sso-jwt-cache-key");

        let opened = unsafe {
            NCryptOpenKey(provider, &mut key, &key_name, 0, 0)
        };

        if opened.is_err() {
            // Key doesn't exist, create it
            unsafe {
                let status = NCryptCreatePersistedKey(
                    provider,
                    &mut key,
                    BCRYPT_ECDH_P256_ALGORITHM,
                    &key_name,
                    0,
                    0,
                );
                if status.is_err() {
                    return Err(anyhow!(
                        "failed to create TPM key: {status:?}"
                    ));
                }

                // If biometric, set UI policy for Windows Hello
                if biometric {
                    let policy = NCRYPT_UI_POLICY {
                        dwVersion: 1,
                        dwFlags: NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG,
                        pszCreationTitle: PCWSTR::null(),
                        pszFriendlyName: PCWSTR::null(),
                        pszDescription: PCWSTR::null(),
                    };
                    let status = NCryptSetProperty(
                        key,
                        NCRYPT_UI_POLICY_PROPERTY,
                        std::slice::from_raw_parts(
                            &policy as *const _ as *const u8,
                            std::mem::size_of::<NCRYPT_UI_POLICY>(),
                        ),
                        NCRYPT_PERSIST_FLAG,
                    );
                    if status.is_err() {
                        eprintln!("warning: failed to set biometric policy: {status:?}");
                    }
                }

                let status = NCryptFinalizeKey(key, 0);
                if status.is_err() {
                    return Err(anyhow!(
                        "failed to finalize TPM key: {status:?}"
                    ));
                }
            }
        }

        // We close handles here and re-open per operation.
        // In a production implementation, we'd hold the handles and
        // implement Drop. For now we store the flag and re-acquire.
        unsafe {
            NCryptFreeObject(key);
            NCryptFreeObject(provider);
        }

        Ok(Self {
            _biometric: biometric,
        })
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
            tpm_encrypt(plaintext)
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
            tpm_decrypt(ciphertext)
        }
    }

    fn destroy(&self) -> Result<()> {
        #[cfg(not(target_os = "windows"))]
        {
            anyhow::bail!("TPM storage is only available on Windows");
        }

        #[cfg(target_os = "windows")]
        {
            tpm_delete_key()
        }
    }
}

#[cfg(target_os = "windows")]
fn tpm_encrypt(plaintext: &[u8]) -> Result<Vec<u8>> {
    use windows::Win32::Security::Cryptography::*;
    use windows::core::*;

    unsafe {
        let mut provider = NCRYPT_PROV_HANDLE::default();
        NCryptOpenStorageProvider(
            &mut provider,
            MS_PLATFORM_CRYPTO_PROVIDER,
            0,
        )
        .map_err(|e| anyhow!("open provider: {e}"))?;

        let mut key = NCRYPT_KEY_HANDLE::default();
        NCryptOpenKey(
            provider,
            &mut key,
            &HSTRING::from("sso-jwt-cache-key"),
            0,
            0,
        )
        .map_err(|e| anyhow!("open key: {e}"))?;

        // Export public key, derive shared secret with ephemeral key,
        // encrypt with AES-GCM. This mirrors the ECIES pattern.
        // For brevity, we use NCryptEncrypt with OAEP padding as a
        // placeholder. A full implementation would do ECDH + AES-GCM.

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

#[cfg(target_os = "windows")]
fn tpm_decrypt(ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use windows::Win32::Security::Cryptography::*;
    use windows::core::*;

    unsafe {
        let mut provider = NCRYPT_PROV_HANDLE::default();
        NCryptOpenStorageProvider(
            &mut provider,
            MS_PLATFORM_CRYPTO_PROVIDER,
            0,
        )
        .map_err(|e| anyhow!("open provider: {e}"))?;

        let mut key = NCRYPT_KEY_HANDLE::default();
        NCryptOpenKey(
            provider,
            &mut key,
            &HSTRING::from("sso-jwt-cache-key"),
            0,
            0,
        )
        .map_err(|e| anyhow!("open key: {e}"))?;

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

        Ok(Zeroizing::new(output))
    }
}

#[cfg(target_os = "windows")]
fn tpm_delete_key() -> Result<()> {
    use windows::Win32::Security::Cryptography::*;
    use windows::core::*;

    unsafe {
        let mut provider = NCRYPT_PROV_HANDLE::default();
        NCryptOpenStorageProvider(
            &mut provider,
            MS_PLATFORM_CRYPTO_PROVIDER,
            0,
        )
        .map_err(|e| anyhow!("open provider: {e}"))?;

        let mut key = NCRYPT_KEY_HANDLE::default();
        let result = NCryptOpenKey(
            provider,
            &mut key,
            &HSTRING::from("sso-jwt-cache-key"),
            0,
            0,
        );

        if result.is_ok() {
            NCryptDeleteKey(key, 0)
                .map_err(|e| anyhow!("delete key: {e}"))?;
        }

        NCryptFreeObject(provider);
        Ok(())
    }
}
