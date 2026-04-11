use anyhow::{anyhow, Result};
use base64::Engine;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct JwtClaims {
    pub iat: Option<u64>,
    pub exp: Option<u64>,
    pub sub: Option<String>,
}

/// Parse a JWT and extract claims from the payload.
/// Does NOT verify the signature -- that's the SSO server's responsibility.
pub fn parse_claims(token: &str) -> Result<JwtClaims> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!(
            "invalid JWT: expected 3 parts, got {}",
            parts.len()
        ));
    }

    let payload = base64url_decode(parts[1])?;
    let claims: JwtClaims = serde_json::from_slice(&payload)
        .map_err(|e| anyhow!("failed to parse JWT payload: {e}"))?;
    Ok(claims)
}

/// Extract the `iat` (issued-at) claim as a Unix timestamp in seconds.
pub fn extract_iat(token: &str) -> Result<u64> {
    let claims = parse_claims(token)?;
    claims
        .iat
        .ok_or_else(|| anyhow!("JWT missing 'iat' claim"))
}

/// Decode base64url with or without padding. JWTs use base64url without
/// padding, but we accept all common variants for robustness.
fn base64url_decode(input: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(input))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(input))
        .or_else(|_| {
            base64::engine::general_purpose::STANDARD_NO_PAD.decode(input)
        })
        .map_err(|e| anyhow!("base64 decode error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn make_jwt(claims_json: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims_json);
        let signature = URL_SAFE_NO_PAD.encode("fakesignature");
        format!("{header}.{payload}.{signature}")
    }

    #[test]
    fn parse_valid_jwt_with_all_claims() {
        let token = make_jwt(
            r#"{"iat":1700000000,"exp":1700086400,"sub":"user@example.com"}"#,
        );
        let claims = parse_claims(&token).unwrap();
        assert_eq!(claims.iat, Some(1700000000));
        assert_eq!(claims.exp, Some(1700086400));
        assert_eq!(claims.sub.as_deref(), Some("user@example.com"));
    }

    #[test]
    fn extract_iat_success() {
        let token = make_jwt(r#"{"iat":1700000000}"#);
        assert_eq!(extract_iat(&token).unwrap(), 1700000000);
    }

    #[test]
    fn extract_iat_missing() {
        let token = make_jwt(r#"{"sub":"user"}"#);
        let err = extract_iat(&token).unwrap_err();
        assert!(err.to_string().contains("missing 'iat'"));
    }

    #[test]
    fn reject_wrong_part_count() {
        assert!(parse_claims("too.many.parts.here.now").is_err());
        assert!(parse_claims("onlyone").is_err());
        assert!(parse_claims("two.parts").is_err());
    }

    #[test]
    fn reject_invalid_base64() {
        assert!(parse_claims("a.!!!invalid!!!.b").is_err());
    }

    #[test]
    fn reject_invalid_json() {
        let header = URL_SAFE_NO_PAD.encode("{}");
        let payload = URL_SAFE_NO_PAD.encode("not json at all");
        let sig = URL_SAFE_NO_PAD.encode("sig");
        assert!(parse_claims(&format!("{header}.{payload}.{sig}")).is_err());
    }

    #[test]
    fn unknown_claims_ignored() {
        let token = make_jwt(
            r#"{"iat":1700000000,"custom":"value","nested":{"a":1}}"#,
        );
        let claims = parse_claims(&token).unwrap();
        assert_eq!(claims.iat, Some(1700000000));
    }

    #[test]
    fn handles_standard_base64_padding() {
        // Some JWT implementations use standard base64 with padding
        let header =
            base64::engine::general_purpose::STANDARD.encode(r#"{"alg":"HS256"}"#);
        let payload =
            base64::engine::general_purpose::STANDARD.encode(r#"{"iat":42}"#);
        let sig = base64::engine::general_purpose::STANDARD.encode("sig");
        let token = format!("{header}.{payload}.{sig}");
        assert_eq!(extract_iat(&token).unwrap(), 42);
    }

    #[test]
    fn minimal_claims() {
        let token = make_jwt(r#"{}"#);
        let claims = parse_claims(&token).unwrap();
        assert_eq!(claims.iat, None);
        assert_eq!(claims.exp, None);
        assert_eq!(claims.sub, None);
    }

    #[test]
    fn large_iat_value() {
        let token = make_jwt(r#"{"iat":4102444800}"#); // 2100-01-01
        assert_eq!(extract_iat(&token).unwrap(), 4102444800);
    }

    #[test]
    fn empty_string_input_errors() {
        let err = parse_claims("").expect_err("empty string should fail");
        assert!(
            err.to_string().contains("expected 3 parts"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn empty_middle_section_errors() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256"}"#);
        let sig = URL_SAFE_NO_PAD.encode("sig");
        // Middle section is empty string — base64 decode of "" is empty bytes,
        // which is not valid JSON.
        let token = format!("{header}..{sig}");
        assert!(
            parse_claims(&token).is_err(),
            "JWT with empty payload section should fail"
        );
    }

    #[test]
    fn iat_float_errors() {
        let token = make_jwt(r#"{"iat":1700000000.5}"#);
        let err = parse_claims(&token).expect_err("float iat should fail for u64");
        assert!(
            err.to_string().contains("failed to parse JWT payload"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn iat_string_errors() {
        let token = make_jwt(r#"{"iat":"1700000000"}"#);
        let err = parse_claims(&token).expect_err("string iat should fail for u64");
        assert!(
            err.to_string().contains("failed to parse JWT payload"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn iat_negative_errors() {
        let token = make_jwt(r#"{"iat":-1}"#);
        let err = parse_claims(&token).expect_err("negative iat should fail for u64");
        assert!(
            err.to_string().contains("failed to parse JWT payload"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn very_long_payload_parses() {
        // Build a JSON payload with a very long string value (>1000 chars)
        let long_value = "a".repeat(1000);
        let json = format!(r#"{{"sub":"{long_value}","iat":42}}"#);
        let token = make_jwt(&json);
        let claims =
            parse_claims(&token).expect("long payload should parse fine");
        assert_eq!(claims.iat, Some(42));
        assert_eq!(
            claims
                .sub
                .as_ref()
                .expect("sub should be present")
                .len(),
            1000
        );
    }

    #[test]
    fn unicode_claims_parse() {
        let token = make_jwt(r#"{"sub":"用户","iat":99}"#);
        let claims =
            parse_claims(&token).expect("unicode claims should parse fine");
        assert_eq!(claims.sub.as_deref(), Some("用户"));
        assert_eq!(claims.iat, Some(99));
    }

    #[test]
    fn whitespace_only_input_errors() {
        let err =
            parse_claims("   ").expect_err("whitespace-only token should fail");
        assert!(
            err.to_string().contains("expected 3 parts"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn dots_only_input_errors() {
        // ".." splits into ["", "", ""] which is 3 parts, but base64 decode
        // of empty string yields empty bytes, and empty bytes aren't valid JSON.
        let err =
            parse_claims("..").expect_err("dots-only token should fail");
        assert!(
            err.to_string().contains("failed to parse JWT payload"),
            "unexpected error: {err}"
        );
    }
}
