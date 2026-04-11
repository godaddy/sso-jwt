use anyhow::{anyhow, Context, Result};
use core_foundation::base::{kCFAllocatorDefault, CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFMutableDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use std::ptr;
use zeroize::Zeroizing;

use super::SecureStorage;

const KEY_LABEL: &str = "com.company.sso-jwt.cache-key";
const KEY_SIZE: i64 = 256;

// Import the sys symbols we need
extern "C" {
    static kSecAttrKeyTypeECSECPrimeRandom: core_foundation::string::CFStringRef;
    static kSecAttrTokenIDSecureEnclave: core_foundation::string::CFStringRef;
    static kSecAttrKeyType: core_foundation::string::CFStringRef;
    static kSecAttrKeySizeInBits: core_foundation::string::CFStringRef;
    static kSecAttrTokenID: core_foundation::string::CFStringRef;
    static kSecAttrIsPermanent: core_foundation::string::CFStringRef;
    static kSecAttrLabel: core_foundation::string::CFStringRef;
    static kSecAttrAccessControl: core_foundation::string::CFStringRef;
    static kSecPrivateKeyAttrs: core_foundation::string::CFStringRef;
    static kSecClass: core_foundation::string::CFStringRef;
    static kSecClassKey: core_foundation::string::CFStringRef;
    static kSecReturnRef: core_foundation::string::CFStringRef;
    static kSecMatchLimit: core_foundation::string::CFStringRef;
    static kSecMatchLimitOne: core_foundation::string::CFStringRef;
    static kSecAttrKeyClass: core_foundation::string::CFStringRef;
    static kSecAttrKeyClassPrivate: core_foundation::string::CFStringRef;
    static kSecAttrAccessibleWhenUnlockedThisDeviceOnly:
        core_foundation::base::CFTypeRef;
    static kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM:
        core_foundation::base::CFTypeRef;

    fn SecKeyCreateRandomKey(
        parameters: core_foundation::dictionary::CFDictionaryRef,
        error: *mut core_foundation::error::CFErrorRef,
    ) -> *mut std::ffi::c_void;

    fn SecKeyCopyPublicKey(
        key: *mut std::ffi::c_void,
    ) -> *mut std::ffi::c_void;

    fn SecKeyCreateEncryptedData(
        key: *mut std::ffi::c_void,
        algorithm: core_foundation::base::CFTypeRef,
        plaintext: core_foundation::data::CFDataRef,
        error: *mut core_foundation::error::CFErrorRef,
    ) -> core_foundation::data::CFDataRef;

    fn SecKeyCreateDecryptedData(
        key: *mut std::ffi::c_void,
        algorithm: core_foundation::base::CFTypeRef,
        ciphertext: core_foundation::data::CFDataRef,
        error: *mut core_foundation::error::CFErrorRef,
    ) -> core_foundation::data::CFDataRef;

    fn SecItemCopyMatching(
        query: core_foundation::dictionary::CFDictionaryRef,
        result: *mut core_foundation::base::CFTypeRef,
    ) -> i32;

    #[allow(dead_code)]
    fn SecItemDelete(
        query: core_foundation::dictionary::CFDictionaryRef,
    ) -> i32;

    fn SecAccessControlCreateWithFlags(
        allocator: core_foundation::base::CFAllocatorRef,
        protection: core_foundation::base::CFTypeRef,
        flags: u64,
        error: *mut core_foundation::error::CFErrorRef,
    ) -> core_foundation::base::CFTypeRef;
}

const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

pub struct SecureEnclaveStorage {
    /// Raw SecKeyRef for the private key (held in Secure Enclave)
    private_key_ref: *mut std::ffi::c_void,
    /// Raw SecKeyRef for the public key
    public_key_ref: *mut std::ffi::c_void,
}

// SecKeyRef is thread-safe for our usage (immutable after creation)
unsafe impl Send for SecureEnclaveStorage {}
unsafe impl Sync for SecureEnclaveStorage {}

impl SecureEnclaveStorage {
    pub fn init(biometric: bool) -> Result<Self> {
        match find_existing_key()? {
            Some(storage) => Ok(storage),
            None => create_new_key(biometric),
        }
    }
}

impl SecureStorage for SecureEnclaveStorage {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        se_encrypt(self.public_key_ref, plaintext)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        se_decrypt(self.private_key_ref, ciphertext)
    }

    fn destroy(&self) -> Result<()> {
        delete_key()
    }
}

impl Drop for SecureEnclaveStorage {
    fn drop(&mut self) {
        unsafe {
            if !self.private_key_ref.is_null() {
                core_foundation::base::CFRelease(
                    self.private_key_ref as core_foundation::base::CFTypeRef,
                );
            }
            if !self.public_key_ref.is_null() {
                core_foundation::base::CFRelease(
                    self.public_key_ref as core_foundation::base::CFTypeRef,
                );
            }
        }
    }
}

fn se_encrypt(
    public_key: *mut std::ffi::c_void,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    unsafe {
        let plain_data = CFData::from_buffer(plaintext);
        let mut error: core_foundation::error::CFErrorRef = ptr::null_mut();

        let encrypted = SecKeyCreateEncryptedData(
            public_key,
            kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
            plain_data.as_concrete_TypeRef(),
            &mut error,
        );

        if encrypted.is_null() {
            return Err(cf_error_to_anyhow(
                error,
                "Secure Enclave encryption failed",
            ));
        }

        let result = CFData::wrap_under_create_rule(encrypted);
        Ok(result.to_vec())
    }
}

fn se_decrypt(
    private_key: *mut std::ffi::c_void,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    unsafe {
        let cipher_data = CFData::from_buffer(ciphertext);
        let mut error: core_foundation::error::CFErrorRef = ptr::null_mut();

        let decrypted = SecKeyCreateDecryptedData(
            private_key,
            kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
            cipher_data.as_concrete_TypeRef(),
            &mut error,
        );

        if decrypted.is_null() {
            return Err(cf_error_to_anyhow(
                error,
                "Secure Enclave decryption failed",
            ));
        }

        let result = CFData::wrap_under_create_rule(decrypted);
        Ok(Zeroizing::new(result.to_vec()))
    }
}

fn find_existing_key() -> Result<Option<SecureEnclaveStorage>> {
    unsafe {
        let mut query = CFMutableDictionary::new();

        query.set(
            CFString::wrap_under_get_rule(kSecClass),
            CFString::wrap_under_get_rule(kSecClassKey).as_CFType(),
        );
        query.set(
            CFString::wrap_under_get_rule(kSecAttrKeyType),
            CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom)
                .as_CFType(),
        );
        query.set(
            CFString::wrap_under_get_rule(kSecAttrLabel),
            CFString::new(KEY_LABEL).as_CFType(),
        );
        query.set(
            CFString::wrap_under_get_rule(kSecReturnRef),
            CFBoolean::true_value().as_CFType(),
        );
        query.set(
            CFString::wrap_under_get_rule(kSecMatchLimit),
            CFString::wrap_under_get_rule(kSecMatchLimitOne).as_CFType(),
        );
        query.set(
            CFString::wrap_under_get_rule(kSecAttrKeyClass),
            CFString::wrap_under_get_rule(kSecAttrKeyClassPrivate)
                .as_CFType(),
        );

        let mut result: core_foundation::base::CFTypeRef = ptr::null_mut();
        let status = SecItemCopyMatching(
            query.as_concrete_TypeRef(),
            &mut result,
        );

        if status == ERR_SEC_ITEM_NOT_FOUND || result.is_null() {
            return Ok(None);
        }
        if status != 0 {
            return Err(anyhow!(
                "Keychain query failed with status {status}"
            ));
        }

        let private_key_ref = result as *mut std::ffi::c_void;
        let public_key_ref = SecKeyCopyPublicKey(private_key_ref);
        if public_key_ref.is_null() {
            core_foundation::base::CFRelease(result);
            return Err(anyhow!(
                "failed to extract public key from SE private key"
            ));
        }

        Ok(Some(SecureEnclaveStorage {
            private_key_ref,
            public_key_ref,
        }))
    }
}

fn create_access_control(biometric: bool) -> Result<core_foundation::base::CFTypeRef> {
    unsafe {
        let mut flags: u64 = 1 << 30; // kSecAccessControlPrivateKeyUsage

        if biometric {
            flags |= 1 << 1; // kSecAccessControlBiometryCurrentSet
        }

        let mut error: core_foundation::error::CFErrorRef = ptr::null_mut();
        let access_control = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &mut error,
        );

        if access_control.is_null() {
            return Err(cf_error_to_anyhow(
                error,
                "failed to create access control",
            ));
        }

        Ok(access_control)
    }
}

fn create_new_key(biometric: bool) -> Result<SecureEnclaveStorage> {
    let access_control = create_access_control(biometric)
        .context("creating SE access control policy")?;

    unsafe {
        let mut attrs = CFMutableDictionary::new();

        attrs.set(
            CFString::wrap_under_get_rule(kSecAttrKeyType),
            CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom)
                .as_CFType(),
        );
        attrs.set(
            CFString::wrap_under_get_rule(kSecAttrKeySizeInBits),
            CFNumber::from(KEY_SIZE).as_CFType(),
        );
        attrs.set(
            CFString::wrap_under_get_rule(kSecAttrTokenID),
            CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave)
                .as_CFType(),
        );

        // Private key attributes
        let mut private_attrs = CFMutableDictionary::new();
        private_attrs.set(
            CFString::wrap_under_get_rule(kSecAttrIsPermanent),
            CFBoolean::true_value().as_CFType(),
        );
        private_attrs.set(
            CFString::wrap_under_get_rule(kSecAttrLabel),
            CFString::new(KEY_LABEL).as_CFType(),
        );
        private_attrs.set(
            CFString::wrap_under_get_rule(kSecAttrAccessControl),
            CFType::wrap_under_get_rule(access_control),
        );

        attrs.set(
            CFString::wrap_under_get_rule(kSecPrivateKeyAttrs),
            private_attrs.as_CFType(),
        );

        let mut error: core_foundation::error::CFErrorRef = ptr::null_mut();
        let key_ref = SecKeyCreateRandomKey(
            attrs.as_concrete_TypeRef(),
            &mut error,
        );

        // Release access control now that key creation is done
        core_foundation::base::CFRelease(access_control);

        if key_ref.is_null() {
            return Err(cf_error_to_anyhow(
                error,
                "failed to create Secure Enclave key. \
                 Does this machine have a Secure Enclave (T2 chip or Apple Silicon)?",
            ));
        }

        let public_key_ref = SecKeyCopyPublicKey(key_ref);
        if public_key_ref.is_null() {
            core_foundation::base::CFRelease(
                key_ref as core_foundation::base::CFTypeRef,
            );
            return Err(anyhow!(
                "failed to extract public key from newly created SE key"
            ));
        }

        Ok(SecureEnclaveStorage {
            private_key_ref: key_ref,
            public_key_ref,
        })
    }
}

#[allow(dead_code)]
fn delete_key() -> Result<()> {
    unsafe {
        let mut query = CFMutableDictionary::new();
        query.set(
            CFString::wrap_under_get_rule(kSecClass),
            CFString::wrap_under_get_rule(kSecClassKey).as_CFType(),
        );
        query.set(
            CFString::wrap_under_get_rule(kSecAttrLabel),
            CFString::new(KEY_LABEL).as_CFType(),
        );

        let status = SecItemDelete(query.as_concrete_TypeRef());

        if status != 0 && status != ERR_SEC_ITEM_NOT_FOUND {
            return Err(anyhow!(
                "failed to delete Keychain key, status: {status}"
            ));
        }

        Ok(())
    }
}

fn cf_error_to_anyhow(
    error: core_foundation::error::CFErrorRef,
    context: &str,
) -> anyhow::Error {
    unsafe {
        if !error.is_null() {
            let cf_error =
                core_foundation::error::CFError::wrap_under_create_rule(error);
            anyhow!("{context}: {cf_error}")
        } else {
            anyhow!("{context}: unknown error")
        }
    }
}
