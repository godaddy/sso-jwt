#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz JWT claims parsing (base64 decode + JSON parse).
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = sso_jwt_lib::jwt::parse_claims(s);
    }
});
