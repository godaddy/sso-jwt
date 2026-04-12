use anyhow::Result;
use zeroize::Zeroizing;

/// Platform-agnostic trait for hardware-backed (or software-backed) secret storage.
/// Each platform implements this with its own backend:
/// - macOS: Secure Enclave via Security.framework ECIES
/// - Windows: TPM 2.0 via CNG
/// - WSL: TPM bridge to Windows host
/// - Linux: D-Bus secret service (software keyring)
pub trait SecureStorage: Send + Sync {
    /// Encrypt plaintext using the hardware-bound key.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt ciphertext using the hardware-bound key.
    /// Returns the plaintext wrapped in `Zeroizing` so it is wiped on drop.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>>;

    /// Delete the hardware-bound key and any cached data.
    #[allow(dead_code)]
    fn destroy(&self) -> Result<()>;
}

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
mod wsl;

/// Initialize the platform-appropriate secure storage backend.
/// Returns an error if the required hardware is not available.
pub fn platform_storage(biometric: bool) -> Result<Box<dyn SecureStorage>> {
    #[cfg(target_os = "macos")]
    {
        let storage = macos::SecureEnclaveStorage::init(biometric)?;
        Ok(Box::new(storage))
    }

    #[cfg(target_os = "windows")]
    {
        let storage = windows::TpmStorage::init(biometric)?;
        Ok(Box::new(storage))
    }

    #[cfg(target_os = "linux")]
    {
        if wsl::is_wsl() {
            let storage = wsl::WslTpmBridge::init(biometric)?;
            Ok(Box::new(storage))
        } else {
            let storage = linux::KeyringStorage::init(biometric)?;
            Ok(Box::new(storage))
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = biometric;
        anyhow::bail!("unsupported platform: no secure storage backend available")
    }
}

/// Mock storage for testing. Uses simple XOR -- obviously not secure,
/// but lets us test cache format and lifecycle logic without real hardware.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    missing_debug_implementations,
    clippy::new_without_default
)]
pub mod mock {
    use super::*;

    pub struct MockStorage {
        key: u8,
    }

    impl MockStorage {
        pub fn new() -> Self {
            Self { key: 0x42 }
        }
    }

    impl SecureStorage for MockStorage {
        fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
            Ok(plaintext.iter().map(|b| b ^ self.key).collect())
        }

        fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(
                ciphertext.iter().map(|b| b ^ self.key).collect(),
            ))
        }

        fn destroy(&self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn mock_roundtrip() {
        let storage = MockStorage::new();
        let plaintext = b"hello world";
        let encrypted = storage.encrypt(plaintext).unwrap();
        assert_ne!(&encrypted, plaintext);
        let decrypted = storage.decrypt(&encrypted).unwrap();
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn mock_roundtrip_various_sizes() {
        let storage = MockStorage::new();
        for size in [0, 1, 100, 10_000] {
            let plaintext = vec![0xAB_u8; size];
            let encrypted = storage.encrypt(&plaintext).unwrap();
            let decrypted = storage.decrypt(&encrypted).unwrap();
            assert_eq!(
                &*decrypted,
                &plaintext[..],
                "roundtrip failed for size {size}"
            );
        }
    }

    #[test]
    fn mock_encrypt_differs_from_plaintext() {
        let storage = MockStorage::new();
        let plaintext = b"sensitive data here";
        let encrypted = storage.encrypt(plaintext).unwrap();
        // XOR with a non-zero key means every non-zero byte changes
        assert_ne!(&encrypted[..], &plaintext[..]);
    }

    #[test]
    fn mock_destroy_succeeds() {
        let storage = MockStorage::new();
        assert!(storage.destroy().is_ok());
    }

    #[test]
    fn mock_encrypt_empty_roundtrip() {
        let storage = MockStorage::new();
        let encrypted = storage.encrypt(b"").unwrap();
        let decrypted = storage.decrypt(&encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn mock_encrypt_single_byte_roundtrip() {
        let storage = MockStorage::new();
        let encrypted = storage.encrypt(&[0x42]).unwrap();
        // 0x42 XOR 0x42 = 0x00
        assert_eq!(&encrypted[..], &[0x00]);
        let decrypted = storage.decrypt(&encrypted).unwrap();
        assert_eq!(&*decrypted, &[0x42]);
    }
}
