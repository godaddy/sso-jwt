use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::time::Duration;

/// Non-secret client identifier. Helps the webservice isolate requests
/// from this client vs. hypothetical other clients.
const CLIENT_ID: &str = "e238e416";

/// Response from the initial device code request.
#[derive(Debug, Deserialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default = "default_interval")]
    pub interval: u64,
    #[serde(default = "default_expires_in")]
    pub expires_in: u64,
}

fn default_interval() -> u64 {
    5
}
fn default_expires_in() -> u64 {
    600
}

/// Response when polling for the access token.
#[derive(Debug, Deserialize)]
struct TokenPollResponse {
    access_token: Option<String>,
    error: Option<String>,
}

/// Request a new device code from the OAuth service.
pub fn get_device_code(
    client: &reqwest::blocking::Client,
    oauth_url: &str,
) -> Result<DeviceCodeResponse> {
    let url = format!("{oauth_url}/token");
    let resp = client
        .post(&url)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("client_id={CLIENT_ID}"))
        .send()
        .context("failed to request device code")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "device code request failed with status {}",
            resp.status()
        ));
    }

    let code: DeviceCodeResponse = resp
        .json()
        .context("failed to parse device code response")?;
    Ok(code)
}

/// Poll the OAuth service until the user authorizes, or timeout.
pub fn poll_for_token(
    client: &reqwest::blocking::Client,
    oauth_url: &str,
    device_code: &str,
    interval: u64,
    expires_in: u64,
) -> Result<String> {
    let url = format!("{oauth_url}/token");
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(expires_in);
    let mut poll_interval = Duration::from_secs(interval);

    loop {
        if start.elapsed() >= timeout {
            return Err(anyhow!(
                "authorization timed out after {expires_in} seconds"
            ));
        }

        std::thread::sleep(poll_interval);

        let resp = client
            .post(&url)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(format!(
                "client_id={CLIENT_ID}&device_code={device_code}"
            ))
            .send()
            .context("failed to poll for token")?;

        let poll: TokenPollResponse =
            resp.json().context("failed to parse token poll response")?;

        if let Some(token) = poll.access_token {
            return Ok(token);
        }

        match poll.error.as_deref() {
            Some("authorization_pending") => {
                // Normal -- keep polling at the standard interval
            }
            Some("slow_down") => {
                // Server asked us to back off
                poll_interval = Duration::from_secs(interval * 2);
            }
            Some(error) => {
                return Err(anyhow!("authorization failed: {error}"));
            }
            None => {
                return Err(anyhow!(
                    "unexpected response: no access_token and no error"
                ));
            }
        }
    }
}

/// Format the user code for display (XXXX-XXXX).
pub fn format_user_code(code: &str) -> String {
    if code.len() >= 8 {
        let upper = code.to_uppercase();
        format!("{}-{}", &upper[..4], &upper[4..8])
    } else {
        code.to_uppercase()
    }
}

/// Open the verification URI in the user's default browser.
/// Falls back to the `$BROWSER` environment variable if the platform
/// opener fails (useful in containers / VS Code devcontainers).
pub fn open_browser(uri: &str) -> Result<()> {
    match open::that(uri) {
        Ok(()) => Ok(()),
        Err(e) => {
            if let Ok(browser) = std::env::var("BROWSER") {
                std::process::Command::new(&browser)
                    .arg(uri)
                    .spawn()
                    .with_context(|| {
                        format!("failed to open browser via $BROWSER ({browser})")
                    })?;
                Ok(())
            } else {
                Err(e).context("failed to open browser")
            }
        }
    }
}

/// Run the full OAuth Device Code flow: request code, prompt user,
/// poll for token.
#[allow(clippy::print_stderr)]
pub fn authenticate(
    oauth_url: &str,
    auto_open: bool,
) -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to create HTTP client")?;

    let code = get_device_code(&client, oauth_url)?;
    let formatted_code = format_user_code(&code.user_code);

    if auto_open {
        match open_browser(&code.verification_uri) {
            Ok(()) => {
                eprintln!("Opening {}", code.verification_uri);
            }
            Err(e) => {
                eprintln!("Could not open browser: {e}");
                eprintln!(
                    "Please open {} in your web browser.",
                    code.verification_uri
                );
            }
        }
    } else {
        eprintln!(
            "Please open {} in your web browser.",
            code.verification_uri
        );
    }

    eprintln!(
        "When prompted, confirm or enter this code: {formatted_code}"
    );

    poll_for_token(
        &client,
        oauth_url,
        &code.device_code,
        code.interval,
        code.expires_in,
    )
}

/// Attempt to refresh a token via the SSO heartbeat endpoint.
/// Returns the new token on success, or None on failure.
pub fn heartbeat_refresh(
    sso_url: &str,
    token: &str,
) -> Option<String> {
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return None,
    };

    let url = format!("{sso_url}/api/token/heartbeat");
    let resp = match client
        .post(&url)
        .header("Authorization", format!("sso-jwt {token}"))
        .send()
    {
        Ok(r) => r,
        Err(_) => return None,
    };

    if resp.status().as_u16() != 201 {
        return None;
    }

    #[derive(Deserialize)]
    struct HeartbeatResponse {
        data: Option<String>,
    }

    let body: HeartbeatResponse = match resp.json() {
        Ok(b) => b,
        Err(_) => return None,
    };

    body.data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_user_code_standard() {
        assert_eq!(format_user_code("abcd1234"), "ABCD-1234");
    }

    #[test]
    fn format_user_code_already_upper() {
        assert_eq!(format_user_code("WXYZ5678"), "WXYZ-5678");
    }

    #[test]
    fn format_user_code_short() {
        assert_eq!(format_user_code("abc"), "ABC");
    }

    #[test]
    fn format_user_code_exactly_eight() {
        assert_eq!(format_user_code("12345678"), "1234-5678");
    }

    #[test]
    fn format_user_code_longer_than_eight() {
        assert_eq!(format_user_code("abcdefghij"), "ABCD-EFGH");
    }

    #[test]
    fn default_interval_value() {
        assert_eq!(default_interval(), 5);
    }

    #[test]
    fn default_expires_in_value() {
        assert_eq!(default_expires_in(), 600);
    }

    #[test]
    fn parse_device_code_response() {
        let json = r#"{
            "device_code": "abc123",
            "user_code": "WXYZ5678",
            "verification_uri": "https://example.com/authorize",
            "interval": 5,
            "expires_in": 600
        }"#;
        let resp: DeviceCodeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.device_code, "abc123");
        assert_eq!(resp.user_code, "WXYZ5678");
        assert_eq!(resp.interval, 5);
        assert_eq!(resp.expires_in, 600);
    }

    #[test]
    fn parse_device_code_response_defaults() {
        let json = r#"{
            "device_code": "abc",
            "user_code": "1234",
            "verification_uri": "https://example.com"
        }"#;
        let resp: DeviceCodeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.interval, 5);
        assert_eq!(resp.expires_in, 600);
    }

    #[test]
    fn parse_token_poll_with_token() {
        let json = r#"{"access_token":"test-token-value-not-a-real-jwt"}"#;
        let resp: TokenPollResponse = serde_json::from_str(json).unwrap();
        assert!(resp.access_token.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn parse_token_poll_pending() {
        let json = r#"{"error":"authorization_pending"}"#;
        let resp: TokenPollResponse = serde_json::from_str(json).unwrap();
        assert!(resp.access_token.is_none());
        assert_eq!(resp.error.as_deref(), Some("authorization_pending"));
    }

    #[test]
    fn parse_heartbeat_response_with_data() {
        #[derive(Deserialize)]
        struct HeartbeatResponse {
            data: Option<String>,
        }
        let json = r#"{"data":"new-token-value"}"#;
        let resp: HeartbeatResponse =
            serde_json::from_str(json).expect("valid heartbeat JSON");
        assert_eq!(resp.data.as_deref(), Some("new-token-value"));
    }

    #[test]
    fn parse_heartbeat_response_with_null_data() {
        #[derive(Deserialize)]
        struct HeartbeatResponse {
            data: Option<String>,
        }
        let json = r#"{"data":null}"#;
        let resp: HeartbeatResponse =
            serde_json::from_str(json).expect("valid heartbeat JSON with null");
        assert!(resp.data.is_none());
    }

    #[test]
    fn parse_token_poll_with_both_token_and_error() {
        // When both access_token and error are present, the code checks
        // access_token first via `if let Some(token) = poll.access_token`
        let json = r#"{"access_token":"my-token","error":"some_error"}"#;
        let resp: TokenPollResponse =
            serde_json::from_str(json).expect("valid poll JSON");
        assert_eq!(resp.access_token.as_deref(), Some("my-token"));
        assert_eq!(resp.error.as_deref(), Some("some_error"));
    }

    #[test]
    fn format_user_code_empty_string() {
        assert_eq!(format_user_code(""), "");
    }

    #[test]
    fn format_user_code_exactly_four() {
        assert_eq!(format_user_code("abcd"), "ABCD");
    }

    #[test]
    fn format_user_code_mixed_case_and_numbers() {
        assert_eq!(format_user_code("aB3dEf9H"), "AB3D-EF9H");
    }

    #[test]
    fn device_code_response_ignores_extra_fields() {
        let json = r#"{
            "device_code": "dc-123",
            "user_code": "UC456789",
            "verification_uri": "https://example.com/verify",
            "interval": 10,
            "expires_in": 300,
            "extra_field": "should be ignored",
            "another": 42
        }"#;
        let resp: DeviceCodeResponse =
            serde_json::from_str(json).expect("extra fields should be ignored");
        assert_eq!(resp.device_code, "dc-123");
        assert_eq!(resp.user_code, "UC456789");
        assert_eq!(resp.interval, 10);
        assert_eq!(resp.expires_in, 300);
    }

    #[test]
    fn parse_token_poll_slow_down() {
        let json = r#"{"error":"slow_down"}"#;
        let resp: TokenPollResponse =
            serde_json::from_str(json).expect("valid slow_down JSON");
        assert!(resp.access_token.is_none());
        assert_eq!(resp.error.as_deref(), Some("slow_down"));
    }

    #[test]
    fn parse_token_poll_access_denied() {
        let json = r#"{"error":"access_denied"}"#;
        let resp: TokenPollResponse =
            serde_json::from_str(json).expect("valid access_denied JSON");
        assert!(resp.access_token.is_none());
        assert_eq!(resp.error.as_deref(), Some("access_denied"));
    }
}
