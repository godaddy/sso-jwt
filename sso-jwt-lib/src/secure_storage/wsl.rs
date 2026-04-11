use anyhow::{anyhow, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

use super::SecureStorage;

const BRIDGE_PATHS: &[&str] = &[
    "/mnt/c/Program Files/sso-jwt/sso-jwt-tpm-bridge.exe",
    "/mnt/c/ProgramData/sso-jwt/sso-jwt-tpm-bridge.exe",
];

/// Detect whether we're running inside WSL.
pub fn is_wsl() -> bool {
    // Primary: WSL sets this environment variable
    if std::env::var("WSL_DISTRO_NAME").is_ok() {
        return true;
    }
    // Secondary: check /proc/version for Microsoft/WSL signature
    if let Ok(version) = std::fs::read_to_string("/proc/version") {
        let lower = version.to_lowercase();
        return lower.contains("microsoft") || lower.contains("wsl");
    }
    false
}

/// JSON-RPC request sent to the bridge process.
#[derive(Serialize)]
struct BridgeRequest {
    method: String,
    params: BridgeParams,
}

#[derive(Serialize)]
struct BridgeParams {
    data: Option<String>,
    biometric: Option<bool>,
}

/// JSON-RPC response received from the bridge process.
#[derive(Deserialize)]
struct BridgeResponse {
    result: Option<String>,
    error: Option<String>,
}

/// WSL TPM bridge client. Spawns sso-jwt-tpm-bridge.exe on the Windows host
/// and communicates via stdin/stdout JSON-RPC.
pub struct WslTpmBridge {
    bridge_path: String,
    biometric: bool,
}

impl WslTpmBridge {
    pub fn init(biometric: bool) -> Result<Self> {
        let bridge_path = find_bridge()?;

        // Send init command to the bridge to ensure TPM key exists
        let bridge = Self {
            bridge_path,
            biometric,
        };
        bridge.call("init", None)?;

        Ok(bridge)
    }

    fn call(&self, method: &str, data: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        let request = BridgeRequest {
            method: method.to_string(),
            params: BridgeParams {
                data: data.map(|d| base64::engine::general_purpose::STANDARD.encode(d)),
                biometric: Some(self.biometric),
            },
        };

        let request_json = serde_json::to_string(&request)?;

        let mut child = Command::new(&self.bridge_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to spawn TPM bridge at {}", self.bridge_path))?;

        // Send request
        if let Some(stdin) = child.stdin.as_mut() {
            writeln!(stdin, "{request_json}")?;
            stdin.flush()?;
        }

        // Read response
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("failed to read bridge stdout"))?;
        let reader = BufReader::new(stdout);
        let mut response_line = String::new();
        let mut buf_reader = reader;
        buf_reader.read_line(&mut response_line)?;

        drop(child.wait());

        if response_line.is_empty() {
            // Try to read stderr for error info
            let stderr = child.stderr.take();
            let mut err_msg = String::new();
            if let Some(mut stderr) = stderr {
                use std::io::Read;
                drop(stderr.read_to_string(&mut err_msg));
            }
            return Err(anyhow!(
                "TPM bridge returned empty response. stderr: {err_msg}"
            ));
        }

        let response: BridgeResponse = serde_json::from_str(response_line.trim())?;

        if let Some(err) = response.error {
            return Err(anyhow!("TPM bridge error: {err}"));
        }

        match response.result {
            Some(b64) => {
                let bytes = base64::engine::general_purpose::STANDARD.decode(&b64)?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }
}

impl SecureStorage for WslTpmBridge {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.call("encrypt", Some(plaintext))?
            .ok_or_else(|| anyhow!("bridge returned no data for encrypt"))
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let data = self
            .call("decrypt", Some(ciphertext))?
            .ok_or_else(|| anyhow!("bridge returned no data for decrypt"))?;
        Ok(Zeroizing::new(data))
    }

    fn destroy(&self) -> Result<()> {
        self.call("destroy", None)?;
        Ok(())
    }
}

fn find_bridge() -> Result<String> {
    for path in BRIDGE_PATHS {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }

    Err(anyhow!(
        "sso-jwt-tpm-bridge.exe not found.\n\
         Install sso-jwt on the Windows host first, then re-run under WSL.\n\
         Expected paths:\n{}",
        BRIDGE_PATHS
            .iter()
            .map(|p| format!("  - {p}"))
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wsl_detection_env_var() {
        // is_wsl() checks WSL_DISTRO_NAME -- we can't easily set this
        // in tests without side effects, so just verify it doesn't crash
        let _ = is_wsl();
    }

    #[test]
    fn bridge_request_serialization() {
        let req = BridgeRequest {
            method: "encrypt".to_string(),
            params: BridgeParams {
                data: Some("aGVsbG8=".to_string()),
                biometric: Some(false),
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("encrypt"));
        assert!(json.contains("aGVsbG8="));
    }

    #[test]
    fn bridge_response_deserialization() {
        let json = r#"{"result":"dGVzdA==","error":null}"#;
        let resp: BridgeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.result.as_deref(), Some("dGVzdA=="));
        assert!(resp.error.is_none());
    }

    #[test]
    fn bridge_response_with_error() {
        let json = r#"{"result":null,"error":"TPM not found"}"#;
        let resp: BridgeResponse = serde_json::from_str(json).unwrap();
        assert!(resp.result.is_none());
        assert_eq!(resp.error.as_deref(), Some("TPM not found"));
    }

    #[test]
    fn bridge_request_serialization_with_none_data() {
        let req = BridgeRequest {
            method: "init".to_string(),
            params: BridgeParams {
                data: None,
                biometric: Some(true),
            },
        };
        let json = serde_json::to_string(&req).expect("serialization should succeed");
        assert!(json.contains("\"method\":\"init\""));
        assert!(json.contains("\"data\":null"));
        assert!(json.contains("\"biometric\":true"));
    }

    #[test]
    fn bridge_response_with_both_result_and_error() {
        let json = r#"{"result":"dGVzdA==","error":"partial failure"}"#;
        let resp: BridgeResponse =
            serde_json::from_str(json).expect("both result and error should parse");
        assert_eq!(resp.result.as_deref(), Some("dGVzdA=="));
        assert_eq!(resp.error.as_deref(), Some("partial failure"));
    }

    #[test]
    fn bridge_response_with_both_null() {
        let json = r#"{"result":null,"error":null}"#;
        let resp: BridgeResponse = serde_json::from_str(json).expect("both null should parse");
        assert!(resp.result.is_none());
        assert!(resp.error.is_none());
    }

    #[test]
    fn find_bridge_returns_descriptive_error() {
        // On non-WSL systems the bridge paths won't exist, so
        // find_bridge() should return an error with the expected paths.
        let err = find_bridge().expect_err("should fail on non-WSL");
        let msg = err.to_string();
        assert!(
            msg.contains("sso-jwt-tpm-bridge.exe not found"),
            "error should mention the missing binary"
        );
        for path in BRIDGE_PATHS {
            assert!(
                msg.contains(path),
                "error should list expected path: {path}"
            );
        }
    }
}
