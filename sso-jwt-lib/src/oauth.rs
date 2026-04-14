use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::time::Duration;

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
///
/// Posts directly to `oauth_url` (the device authorization endpoint).
/// Sends `Accept: application/json` for RFC 8628 compliance.
pub fn get_device_code(
    client: &reqwest::blocking::Client,
    oauth_url: &str,
    client_id: &str,
) -> Result<DeviceCodeResponse> {
    let resp = client
        .post(oauth_url)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .form(&[("client_id", client_id)])
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
///
/// When `token_url` is `Some`, polls that endpoint. Otherwise falls back to
/// `oauth_url` (backward compat for services that use a single endpoint).
/// Includes `grant_type=urn:ietf:params:oauth:grant-type:device_code` per
/// RFC 8628.
pub fn poll_for_token(
    client: &reqwest::blocking::Client,
    oauth_url: &str,
    token_url: Option<&str>,
    client_id: &str,
    device_code: &str,
    interval: u64,
    expires_in: u64,
) -> Result<String> {
    let url = token_url.unwrap_or(oauth_url);
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
            .post(url)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("accept", "application/json")
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", client_id),
                ("device_code", device_code),
            ])
            .send()
            .context("failed to poll for token")?;

        let poll: TokenPollResponse = resp.json().context("failed to parse token poll response")?;

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
                return Err(anyhow!("unexpected response: no access_token and no error"));
            }
        }
    }
}

/// Format the user code for display (XXXX-XXXX).
pub fn format_user_code(code: &str) -> String {
    let upper = code.to_uppercase();
    upper
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("-")
}

/// Open the verification URI in the user's default browser.
/// Falls back to the `$BROWSER` environment variable if the platform
/// opener fails (useful in containers / VS Code devcontainers).
pub fn open_browser(uri: &str) -> Result<()> {
    match open::that(uri) {
        Ok(()) => Ok(()),
        Err(e) => {
            if let Ok(browser) = std::env::var("BROWSER") {
                let mut parts = shell_words::split(&browser)
                    .with_context(|| format!("failed to parse $BROWSER ({browser})"))?;
                let program = parts
                    .first()
                    .cloned()
                    .ok_or_else(|| anyhow!("$BROWSER is set but empty"))?;
                std::process::Command::new(program)
                    .args(parts.drain(1..))
                    .arg(uri)
                    .spawn()
                    .with_context(|| format!("failed to open browser via $BROWSER ({browser})"))?;
                Ok(())
            } else {
                Err(e).context("failed to open browser")
            }
        }
    }
}

/// Run the full OAuth Device Code flow: request code, prompt user,
/// poll for token.
///
/// `token_url` is the separate token endpoint for polling. When `None`,
/// `oauth_url` is used for both device authorization and token polling
/// (backward compat).
#[allow(clippy::print_stderr)]
pub fn authenticate(
    oauth_url: &str,
    token_url: Option<&str>,
    client_id: &str,
    auto_open: bool,
) -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to create HTTP client")?;

    let code = get_device_code(&client, oauth_url, client_id)?;
    let formatted_code = format_user_code(&code.user_code);

    if auto_open {
        match open_browser(&code.verification_uri) {
            Ok(()) => {
                eprintln!("Opening {}", code.verification_uri);
            }
            Err(e) => {
                eprintln!("Could not open browser: {e}");
                eprintln!("Please open {} in your web browser.", code.verification_uri);
            }
        }
    } else {
        eprintln!("Please open {} in your web browser.", code.verification_uri);
    }

    eprintln!("When prompted, confirm or enter this code: {formatted_code}");

    poll_for_token(
        &client,
        oauth_url,
        token_url,
        client_id,
        &code.device_code,
        code.interval,
        code.expires_in,
    )
}

/// Attempt to refresh a token via the heartbeat endpoint.
/// Returns the new token on success, or None on failure.
/// The caller passes the full heartbeat URL directly.
pub fn heartbeat_refresh(heartbeat_url: &str, token: &str) -> Option<String> {
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return None,
    };

    let resp = match client
        .post(heartbeat_url)
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
        assert_eq!(format_user_code("abcdefghij"), "ABCD-EFGH-IJ");
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
        let resp: DeviceCodeResponse = serde_json::from_str(json).expect("valid device code JSON");
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
        let resp: DeviceCodeResponse =
            serde_json::from_str(json).expect("valid device code JSON with defaults");
        assert_eq!(resp.interval, 5);
        assert_eq!(resp.expires_in, 600);
    }

    #[test]
    fn parse_token_poll_with_token() {
        let json = r#"{"access_token":"test-token-value-not-a-real-jwt"}"#;
        let resp: TokenPollResponse =
            serde_json::from_str(json).expect("valid poll JSON with token");
        assert!(resp.access_token.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn parse_token_poll_pending() {
        let json = r#"{"error":"authorization_pending"}"#;
        let resp: TokenPollResponse = serde_json::from_str(json).expect("valid poll JSON pending");
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
        let resp: HeartbeatResponse = serde_json::from_str(json).expect("valid heartbeat JSON");
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
        let json = r#"{"access_token":"my-token","error":"some_error"}"#;
        let resp: TokenPollResponse = serde_json::from_str(json).expect("valid poll JSON");
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
    fn format_user_code_long_values_keep_all_characters() {
        assert_eq!(format_user_code("abcdefghijkl"), "ABCD-EFGH-IJKL");
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
        let resp: TokenPollResponse = serde_json::from_str(json).expect("valid slow_down JSON");
        assert!(resp.access_token.is_none());
        assert_eq!(resp.error.as_deref(), Some("slow_down"));
    }

    #[test]
    fn parse_token_poll_access_denied() {
        let json = r#"{"error":"access_denied"}"#;
        let resp: TokenPollResponse = serde_json::from_str(json).expect("valid access_denied JSON");
        assert!(resp.access_token.is_none());
        assert_eq!(resp.error.as_deref(), Some("access_denied"));
    }

    #[test]
    fn get_device_code_posts_to_oauth_url_directly() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .match_header("accept", "application/json")
            .match_header("content-type", "application/x-www-form-urlencoded")
            .match_body("client_id=test-client")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                    "device_code": "dev123",
                    "user_code": "ABCD1234",
                    "verification_uri": "https://example.com/verify"
                }"#,
            )
            .create();

        let client = reqwest::blocking::Client::new();
        let resp = get_device_code(&client, &server.url(), "test-client").expect("should succeed");
        assert_eq!(resp.device_code, "dev123");
        assert_eq!(resp.user_code, "ABCD1234");
        mock.assert();
    }

    #[test]
    fn get_device_code_no_token_suffix() {
        // Verify that /token is NOT appended to the URL
        let mut server = mockito::Server::new();
        let _wrong = server.mock("POST", "/token").with_status(404).create();
        let correct = server
            .mock("POST", "/device/code")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                    "device_code": "dc",
                    "user_code": "UC123456",
                    "verification_uri": "https://example.com"
                }"#,
            )
            .create();

        let client = reqwest::blocking::Client::new();
        let url = format!("{}/device/code", server.url());
        let resp = get_device_code(&client, &url, "cid").expect("should hit /device/code");
        assert_eq!(resp.device_code, "dc");
        correct.assert();
    }

    #[test]
    fn poll_for_token_uses_token_url_when_provided() {
        let mut server = mockito::Server::new();
        let token_mock = server
            .mock("POST", "/token")
            .match_header("accept", "application/json")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::Regex(
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code".to_string(),
                ),
                mockito::Matcher::Regex("client_id=cid".to_string()),
                mockito::Matcher::Regex("device_code=dc".to_string()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"the-token"}"#)
            .create();

        let client = reqwest::blocking::Client::new();
        let token_url = format!("{}/token", server.url());
        let oauth_url = format!("{}/should-not-be-used", server.url());
        let result = poll_for_token(&client, &oauth_url, Some(&token_url), "cid", "dc", 0, 10)
            .expect("should succeed");
        assert_eq!(result, "the-token");
        token_mock.assert();
    }

    #[test]
    fn poll_for_token_falls_back_to_oauth_url() {
        let mut server = mockito::Server::new();
        let oauth_mock = server
            .mock("POST", "/device")
            .match_header("accept", "application/json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"fallback-token"}"#)
            .create();

        let client = reqwest::blocking::Client::new();
        let oauth_url = format!("{}/device", server.url());
        let result = poll_for_token(&client, &oauth_url, None, "cid", "dc", 0, 10)
            .expect("should succeed using oauth_url fallback");
        assert_eq!(result, "fallback-token");
        oauth_mock.assert();
    }

    #[test]
    fn poll_for_token_includes_grant_type() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/token")
            .match_body(mockito::Matcher::Regex(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code".to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"tok"}"#)
            .create();

        let client = reqwest::blocking::Client::new();
        let url = format!("{}/token", server.url());
        drop(poll_for_token(&client, &url, None, "c", "d", 0, 10));
        mock.assert();
    }

    #[test]
    fn parse_token_poll_empty_object() {
        // No access_token and no error field
        let json = r#"{}"#;
        let resp: TokenPollResponse = serde_json::from_str(json).expect("valid JSON");
        assert!(resp.access_token.is_none());
        assert!(resp.error.is_none());
    }

    #[test]
    fn parse_token_poll_expired_token_error() {
        let json = r#"{"error":"expired_token"}"#;
        let resp: TokenPollResponse = serde_json::from_str(json).expect("valid JSON");
        assert!(resp.access_token.is_none());
        assert_eq!(resp.error.as_deref(), Some("expired_token"));
    }

    #[test]
    fn device_code_response_with_only_required_fields() {
        // Only the three required fields, interval and expires_in use defaults
        let json = r#"{
            "device_code": "minimal",
            "user_code": "12345678",
            "verification_uri": "https://example.com"
        }"#;
        let resp: DeviceCodeResponse = serde_json::from_str(json).expect("valid device code JSON");
        assert_eq!(resp.device_code, "minimal");
        assert_eq!(resp.interval, 5);
        assert_eq!(resp.expires_in, 600);
    }

    #[test]
    fn parse_heartbeat_response_missing_data_field() {
        #[derive(Deserialize)]
        struct HeartbeatResponse {
            data: Option<String>,
        }
        // Empty object — data field missing entirely
        let json = r#"{}"#;
        let resp: HeartbeatResponse = serde_json::from_str(json).expect("valid JSON");
        assert!(resp.data.is_none());
    }

    #[test]
    fn get_device_code_non_success_status_returns_error() {
        let mut server = mockito::Server::new();
        let _mock = server
            .mock("POST", "/")
            .with_status(500)
            .with_body("internal error")
            .create();

        let client = reqwest::blocking::Client::new();
        let result = get_device_code(&client, &server.url(), "cid");
        assert!(result.is_err());
        let err_msg = result.expect_err("should be an error").to_string();
        assert!(
            err_msg.contains("500"),
            "error should mention status code, got: {err_msg}"
        );
    }

    #[test]
    fn get_device_code_url_encodes_client_id() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .match_body("client_id=client%2Fid%2Bwith+spaces")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                    "device_code": "dev123",
                    "user_code": "ABCD1234",
                    "verification_uri": "https://example.com/verify"
                }"#,
            )
            .create();

        let client = reqwest::blocking::Client::new();
        drop(
            get_device_code(&client, &server.url(), "client/id+with spaces")
                .expect("device code request should succeed"),
        );
        mock.assert();
    }

    #[test]
    fn poll_for_token_url_encodes_parameters() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/token")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::Regex("client_id=client%2Fid%2Bwith\\+spaces".to_string()),
                mockito::Matcher::Regex("device_code=device%2Bcode%2Fvalue".to_string()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"tok"}"#)
            .create();

        let client = reqwest::blocking::Client::new();
        let url = format!("{}/token", server.url());
        drop(
            poll_for_token(
                &client,
                &url,
                None,
                "client/id+with spaces",
                "device+code/value",
                0,
                10,
            )
            .expect("token poll should succeed"),
        );
        mock.assert();
    }

    #[test]
    fn browser_command_parser_handles_flags() {
        let parts =
            shell_words::split("firefox --private-window").expect("browser command should parse");
        assert_eq!(parts, vec!["firefox", "--private-window"]);
    }
}
