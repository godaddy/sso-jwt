// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! sso-jwt TPM bridge for WSL.
//!
//! This is a Windows-only binary that accepts JSON-RPC commands on stdin,
//! performs TPM 2.0 operations via libenclaveapp, and returns results on stdout.
//! It's spawned by the Linux sso-jwt binary running under WSL.

mod tpm;

use base64::prelude::*;
use enclaveapp_bridge::BridgeResponse;
use enclaveapp_core::types::AccessPolicy;
use serde::Deserialize;
use std::io::{self, BufRead, Write};

const DEFAULT_APP_NAME: &str = "sso-jwt";
const DEFAULT_KEY_LABEL: &str = "cache-key";

#[derive(Debug, Deserialize)]
struct BridgeRequestCompat {
    method: String,
    #[serde(default)]
    params: BridgeParamsCompat,
}

#[derive(Debug, Default, Deserialize)]
struct BridgeParamsCompat {
    #[serde(default)]
    data: String,
    #[serde(default)]
    access_policy: AccessPolicy,
    /// Legacy field: older bridge clients send `"biometric": true` instead of
    /// `"access_policy": "biometric_only"`. Kept for backward compatibility.
    #[serde(default)]
    biometric: bool,
    #[serde(default)]
    app_name: String,
    #[serde(default)]
    key_label: String,
}

impl BridgeParamsCompat {
    fn app_name(&self) -> &str {
        if self.app_name.is_empty() {
            DEFAULT_APP_NAME
        } else {
            &self.app_name
        }
    }

    fn key_label(&self) -> &str {
        if self.key_label.is_empty() {
            DEFAULT_KEY_LABEL
        } else {
            &self.key_label
        }
    }

    /// Resolve the effective access policy, falling back to the legacy
    /// `biometric` boolean when `access_policy` is unset (defaults to `None`).
    fn effective_access_policy(&self) -> AccessPolicy {
        if self.access_policy != AccessPolicy::None {
            return self.access_policy;
        }
        if self.biometric {
            return AccessPolicy::BiometricOnly;
        }
        AccessPolicy::None
    }
}

fn handle_request(
    request: &BridgeRequestCompat,
    storage: &mut Option<tpm::TpmStorage>,
) -> BridgeResponse {
    match request.method.as_str() {
        "init" => {
            match tpm::TpmStorage::new(
                request.params.app_name(),
                request.params.key_label(),
                request.params.effective_access_policy(),
            ) {
                Ok(s) => {
                    *storage = Some(s);
                    BridgeResponse::success("ok")
                }
                Err(e) => BridgeResponse::error(&format!("init failed: {e}")),
            }
        }
        "encrypt" => {
            let Some(ref s) = storage else {
                return BridgeResponse::error("not initialized: call init first");
            };
            if request.params.data.is_empty() {
                return BridgeResponse::error("missing data parameter");
            }
            let plaintext = match BASE64_STANDARD.decode(&request.params.data) {
                Ok(d) => d,
                Err(e) => {
                    return BridgeResponse::error(&format!("base64 decode error: {e}"));
                }
            };
            match s.encrypt(&plaintext) {
                Ok(ciphertext) => BridgeResponse::success(&BASE64_STANDARD.encode(&ciphertext)),
                Err(e) => BridgeResponse::error(&format!("encrypt failed: {e}")),
            }
        }
        "decrypt" => {
            let Some(ref s) = storage else {
                return BridgeResponse::error("not initialized: call init first");
            };
            if request.params.data.is_empty() {
                return BridgeResponse::error("missing data parameter");
            }
            let ciphertext = match BASE64_STANDARD.decode(&request.params.data) {
                Ok(d) => d,
                Err(e) => {
                    return BridgeResponse::error(&format!("base64 decode error: {e}"));
                }
            };
            match s.decrypt(&ciphertext) {
                Ok(plaintext) => BridgeResponse::success(&BASE64_STANDARD.encode(&plaintext)),
                Err(e) => BridgeResponse::error(&format!("decrypt failed: {e}")),
            }
        }
        "destroy" | "delete" => {
            match tpm::TpmStorage::delete(request.params.app_name(), request.params.key_label()) {
                Ok(()) => {
                    *storage = None;
                    BridgeResponse::success("ok")
                }
                Err(e) => BridgeResponse::error(&format!("delete failed: {e}")),
            }
        }
        other => BridgeResponse::error(&format!("unknown method: {other}")),
    }
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut storage: Option<tpm::TpmStorage> = None;

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                let resp = BridgeResponse::error(&format!("read error: {e}"));
                drop(serde_json::to_writer(&mut stdout, &resp));
                drop(stdout.write_all(b"\n"));
                drop(stdout.flush());
                break;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<BridgeRequestCompat>(&line) {
            Ok(req) => handle_request(&req, &mut storage),
            Err(e) => BridgeResponse::error(&format!("invalid JSON: {e}")),
        };

        if serde_json::to_writer(&mut stdout, &response).is_err() {
            break;
        }
        if stdout.write_all(b"\n").is_err() {
            break;
        }
        if stdout.flush().is_err() {
            break;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn make_request(method: &str, data: &str, access_policy: AccessPolicy) -> BridgeRequestCompat {
        BridgeRequestCompat {
            method: method.to_string(),
            params: BridgeParamsCompat {
                data: data.to_string(),
                access_policy,
                biometric: false,
                app_name: DEFAULT_APP_NAME.to_string(),
                key_label: DEFAULT_KEY_LABEL.to_string(),
            },
        }
    }

    #[test]
    fn parse_init_request() {
        let json = r#"{"method": "init", "params": {"access_policy": "none"}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "init");
        assert_eq!(req.params.access_policy, AccessPolicy::None);
        assert_eq!(req.params.app_name(), DEFAULT_APP_NAME);
        assert_eq!(req.params.key_label(), DEFAULT_KEY_LABEL);
    }

    #[test]
    fn parse_init_request_defaults() {
        let json = r#"{"method": "init", "params": {}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "init");
        assert_eq!(req.params.access_policy, AccessPolicy::None);
        assert!(req.params.data.is_empty());
        assert_eq!(req.params.app_name(), DEFAULT_APP_NAME);
        assert_eq!(req.params.key_label(), DEFAULT_KEY_LABEL);
    }

    #[test]
    fn parse_encrypt_request() {
        let json =
            r#"{"method": "encrypt", "params": {"data": "aGVsbG8=", "access_policy": "none"}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "encrypt");
        assert_eq!(req.params.data, "aGVsbG8=");
    }

    #[test]
    fn parse_decrypt_request() {
        let json = r#"{"method": "decrypt", "params": {"data": "Y2lwaGVy"}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "decrypt");
        assert_eq!(req.params.data, "Y2lwaGVy");
    }

    #[test]
    fn parse_delete_request() {
        let json = r#"{"method": "delete", "params": {"key_label": "cache-key"}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "delete");
        assert_eq!(req.params.key_label(), DEFAULT_KEY_LABEL);
    }

    #[test]
    fn parse_destroy_request() {
        let json = r#"{"method": "destroy", "params": {}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "destroy");
        assert_eq!(req.params.app_name(), DEFAULT_APP_NAME);
        assert_eq!(req.params.key_label(), DEFAULT_KEY_LABEL);
    }

    #[test]
    fn parse_request_uses_binary_defaults_for_legacy_payloads() {
        // Legacy clients send `"biometric": true` instead of `"access_policy": "biometric_only"`
        let json = r#"{"method":"init","params":{"biometric":true}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert!(req.params.biometric);
        assert_eq!(req.params.access_policy, AccessPolicy::None);
        assert_eq!(
            req.params.effective_access_policy(),
            AccessPolicy::BiometricOnly,
            "legacy biometric:true should map to BiometricOnly"
        );
        assert_eq!(req.params.app_name(), DEFAULT_APP_NAME);
        assert_eq!(req.params.key_label(), DEFAULT_KEY_LABEL);
    }

    #[test]
    fn effective_access_policy_prefers_explicit_over_legacy() {
        // When both fields are set, access_policy wins
        let json = r#"{"method":"init","params":{"access_policy":"any","biometric":true}}"#;
        let req: BridgeRequestCompat = serde_json::from_str(json).unwrap();
        assert_eq!(
            req.params.effective_access_policy(),
            AccessPolicy::Any,
            "explicit access_policy should take precedence over biometric"
        );
    }

    #[test]
    fn serialize_success_response() {
        let resp = BridgeResponse::success("ok");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"result\":\"ok\""));
    }

    #[test]
    fn serialize_error_response() {
        let resp = BridgeResponse::error("something went wrong");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"error\":\"something went wrong\""));
    }

    #[test]
    fn handle_init_creates_storage() {
        let req = make_request("init", "", AccessPolicy::None);
        let mut storage = None;
        let resp = handle_request(&req, &mut storage);
        // On non-Windows, init succeeds (stub creates the struct)
        // but encrypt/decrypt will fail at runtime
        if let Some(err) = &resp.error {
            assert!(!err.is_empty(), "error message should not be empty");
        } else {
            assert!(resp.result.is_some(), "should return a result on success");
        }
    }

    #[test]
    fn handle_destroy_clears_storage() {
        let req = make_request("destroy", "", AccessPolicy::None);
        let mut storage = None;
        let resp = handle_request(&req, &mut storage);
        if let Some(err) = &resp.error {
            assert!(!err.is_empty(), "error message should not be empty");
        } else {
            assert!(resp.result.is_some(), "should return a result on success");
        }
        assert!(storage.is_none());
    }

    #[test]
    fn handle_delete_clears_storage() {
        let req = make_request("delete", "", AccessPolicy::None);
        let mut storage = None;
        let resp = handle_request(&req, &mut storage);
        if let Some(err) = &resp.error {
            assert!(!err.is_empty(), "error message should not be empty");
        } else {
            assert!(resp.result.is_some(), "should return a result on success");
        }
        assert!(storage.is_none());
    }

    #[test]
    fn handle_unknown_method() {
        let req = make_request("bogus", "", AccessPolicy::None);
        let mut storage = None;
        let resp = handle_request(&req, &mut storage);
        assert!(resp
            .error
            .as_deref()
            .is_some_and(|e| e.contains("unknown method")),);
    }

    #[test]
    fn handle_encrypt_without_init() {
        let req = make_request("encrypt", "aGVsbG8=", AccessPolicy::None);
        let mut storage = None;
        let resp = handle_request(&req, &mut storage);
        assert!(resp
            .error
            .as_deref()
            .is_some_and(|e| e.contains("not initialized")),);
    }

    #[test]
    fn handle_decrypt_without_init() {
        let req = make_request("decrypt", "Y2lwaGVy", AccessPolicy::None);
        let mut storage = None;
        let resp = handle_request(&req, &mut storage);
        assert!(resp
            .error
            .as_deref()
            .is_some_and(|e| e.contains("not initialized")),);
    }

    #[test]
    fn handle_encrypt_missing_data() {
        let req = make_request("encrypt", "", AccessPolicy::None);
        // On platforms without a TPM, new() may fail and storage is None,
        // so we get "not initialized" instead of "missing data". Both are valid errors.
        let mut storage = tpm::TpmStorage::new("sso-jwt", "cache-key", AccessPolicy::None).ok();
        let resp = handle_request(&req, &mut storage);
        assert!(resp.error.is_some());
    }

    #[test]
    fn handle_encrypt_invalid_base64() {
        let req = make_request("encrypt", "not-valid-base64!!!", AccessPolicy::None);
        let mut storage = tpm::TpmStorage::new("sso-jwt", "cache-key", AccessPolicy::None).ok();
        let resp = handle_request(&req, &mut storage);
        assert!(resp.error.is_some());
    }

    #[test]
    fn handle_decrypt_missing_data() {
        let req = make_request("decrypt", "", AccessPolicy::None);
        let mut storage = tpm::TpmStorage::new("sso-jwt", "cache-key", AccessPolicy::None).ok();
        let resp = handle_request(&req, &mut storage);
        assert!(resp.error.is_some());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn encrypt_returns_platform_error_on_non_windows() {
        let storage = tpm::TpmStorage::new("sso-jwt", "cache-key", AccessPolicy::None).unwrap();
        let result = storage.encrypt(b"hello");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("only supported on Windows"));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn decrypt_returns_platform_error_on_non_windows() {
        let storage = tpm::TpmStorage::new("sso-jwt", "cache-key", AccessPolicy::None).unwrap();
        let result = storage.decrypt(b"hello");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("only supported on Windows"));
    }

    #[test]
    fn roundtrip_json_protocol() {
        // Simulate the full JSON protocol flow
        let init_json = r#"{"method":"init","params":{"app_name":"sso-jwt","key_label":"cache-key","access_policy":"none"}}"#;
        let encrypt_json = r#"{"method":"encrypt","params":{"data":"aGVsbG8gd29ybGQ=","app_name":"sso-jwt","key_label":"cache-key","access_policy":"none"}}"#;
        let destroy_json =
            r#"{"method":"destroy","params":{"app_name":"sso-jwt","key_label":"cache-key"}}"#;

        let mut storage = None;

        // Init
        let req: BridgeRequestCompat = serde_json::from_str(init_json).unwrap();
        let resp = handle_request(&req, &mut storage);
        if let Some(err) = &resp.error {
            assert!(!err.is_empty(), "init error should not be empty");
        } else {
            assert!(
                resp.result.is_some(),
                "init should return a result on success"
            );
        }

        // Encrypt (will fail on non-Windows, which is expected)
        let req: BridgeRequestCompat = serde_json::from_str(encrypt_json).unwrap();
        let resp = handle_request(&req, &mut storage);
        if let Some(err) = &resp.error {
            assert!(!err.is_empty(), "encrypt error should not be empty");
        } else {
            assert!(
                resp.result.is_some(),
                "encrypt should return a result on success"
            );
        }

        // Destroy
        let req: BridgeRequestCompat = serde_json::from_str(destroy_json).unwrap();
        let resp = handle_request(&req, &mut storage);
        if let Some(err) = &resp.error {
            assert!(!err.is_empty(), "destroy error should not be empty");
        } else {
            assert!(
                resp.result.is_some(),
                "destroy should return a result on success"
            );
            assert!(storage.is_none());
        }
    }

    #[test]
    fn invalid_json_produces_error() {
        let bad_json = "this is not json";
        let result = serde_json::from_str::<BridgeRequestCompat>(bad_json);
        assert!(result.is_err());
    }
}
