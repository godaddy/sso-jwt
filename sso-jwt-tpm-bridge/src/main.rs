//! sso-jwt TPM bridge for WSL.
//!
//! This is a Windows-only binary that accepts JSON-RPC commands on stdin,
//! performs TPM 2.0 operations via CNG, and returns results on stdout.
//! It's spawned by the Linux sso-jwt binary running under WSL.
//!
//! Protocol:
//!   Request:  {"method":"encrypt|decrypt|init|destroy","params":{"data":"<base64>","biometric":false}}
//!   Response: {"result":"<base64>","error":null}
//!   Error:    {"result":null,"error":"description"}

use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
mod tpm;

#[derive(Deserialize)]
#[allow(dead_code)]
struct Request {
    method: String,
    params: Params,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct Params {
    data: Option<String>,
    biometric: Option<bool>,
}

#[derive(Serialize)]
struct Response {
    result: Option<String>,
    error: Option<String>,
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                let resp = Response {
                    result: None,
                    error: Some(format!("read error: {e}")),
                };
                if let Ok(json) = serde_json::to_string(&resp) {
                    drop(writeln!(stdout, "{json}"));
                }
                drop(stdout.flush());
                continue;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let resp = handle_request(&line);
        if let Ok(json) = serde_json::to_string(&resp) {
            drop(writeln!(stdout, "{json}"));
        }
        drop(stdout.flush());
    }
}

fn handle_request(line: &str) -> Response {
    let req: Request = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            return Response {
                result: None,
                error: Some(format!("invalid request: {e}")),
            };
        }
    };

    #[cfg(target_os = "windows")]
    {
        handle_request_windows(&req)
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = &req;
        Response {
            result: None,
            error: Some("TPM bridge is only available on Windows".to_string()),
        }
    }
}

#[cfg(target_os = "windows")]
fn handle_request_windows(req: &Request) -> Response {
    use base64::Engine;

    let biometric = req.params.biometric.unwrap_or(false);

    match req.method.as_str() {
        "init" => match tpm::ensure_key(biometric) {
            Ok(()) => Response {
                result: None,
                error: None,
            },
            Err(e) => Response {
                result: None,
                error: Some(format!("{e}")),
            },
        },
        "encrypt" => {
            let data = match &req.params.data {
                Some(d) => match base64::engine::general_purpose::STANDARD.decode(d) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        return Response {
                            result: None,
                            error: Some(format!("bad base64: {e}")),
                        };
                    }
                },
                None => {
                    return Response {
                        result: None,
                        error: Some("missing data parameter".to_string()),
                    };
                }
            };

            match tpm::encrypt(&data) {
                Ok(encrypted) => Response {
                    result: Some(base64::engine::general_purpose::STANDARD.encode(&encrypted)),
                    error: None,
                },
                Err(e) => Response {
                    result: None,
                    error: Some(format!("{e}")),
                },
            }
        }
        "decrypt" => {
            let data = match &req.params.data {
                Some(d) => match base64::engine::general_purpose::STANDARD.decode(d) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        return Response {
                            result: None,
                            error: Some(format!("bad base64: {e}")),
                        };
                    }
                },
                None => {
                    return Response {
                        result: None,
                        error: Some("missing data parameter".to_string()),
                    };
                }
            };

            match tpm::decrypt(&data) {
                Ok(decrypted) => Response {
                    result: Some(base64::engine::general_purpose::STANDARD.encode(&decrypted)),
                    error: None,
                },
                Err(e) => Response {
                    result: None,
                    error: Some(format!("{e}")),
                },
            }
        }
        "destroy" => match tpm::destroy() {
            Ok(()) => Response {
                result: None,
                error: None,
            },
            Err(e) => Response {
                result: None,
                error: Some(format!("{e}")),
            },
        },
        other => Response {
            result: None,
            error: Some(format!("unknown method: {other}")),
        },
    }
}
