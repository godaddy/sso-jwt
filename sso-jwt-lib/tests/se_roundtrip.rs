//! Integration test: Secure Enclave encrypt/decrypt roundtrip via libenclaveapp.
//! Only runs on macOS with hardware available.
//! Set SSO_JWT_TEST_SE=1 to enable.

#[test]
fn se_encrypt_decrypt_roundtrip() {
    if std::env::var("SSO_JWT_TEST_SE").is_err() {
        eprintln!("skipping: set SSO_JWT_TEST_SE=1 to run hardware tests");
        return;
    }

    let storage =
        sso_jwt_lib::secure_storage::platform_storage(false).expect("failed to create storage");

    // Normal JWT-like data
    let plaintext = b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzEwMDAwMDAwfQ.fake";
    let ciphertext = storage.encrypt(plaintext).expect("encrypt failed");
    assert_ne!(ciphertext, plaintext);
    let decrypted = storage.decrypt(&ciphertext).expect("decrypt failed");
    assert_eq!(&*decrypted, plaintext);
    eprintln!("JWT roundtrip: {} bytes OK", plaintext.len());

    // Empty data
    let empty_ct = storage.encrypt(b"").expect("encrypt empty failed");
    let empty_pt = storage.decrypt(&empty_ct).expect("decrypt empty failed");
    assert!(empty_pt.is_empty());
    eprintln!("Empty roundtrip OK");

    // Large data (100KB)
    let large = vec![0x42u8; 100_000];
    let large_ct = storage.encrypt(&large).expect("encrypt large failed");
    let large_pt = storage.decrypt(&large_ct).expect("decrypt large failed");
    assert_eq!(&*large_pt, &large);
    eprintln!("Large (100KB) roundtrip OK");

    eprintln!("ALL PASSED: Secure Enclave via libenclaveapp CryptoKit");
}
