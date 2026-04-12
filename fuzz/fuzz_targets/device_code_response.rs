#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the OAuth device code response JSON parser.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<sso_jwt_lib::oauth::DeviceCodeResponse>(s);
    }
});
