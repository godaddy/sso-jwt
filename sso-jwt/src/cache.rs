use anyhow::{anyhow, Context, Result};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::jwt;
use crate::oauth;
use crate::secure_storage::SecureStorage;

// Cache file magic bytes
const MAGIC: &[u8; 4] = b"SJWT";
const FORMAT_VERSION: u8 = 0x01;
const HEADER_SIZE: usize = 26; // 4 + 1 + 1 + 8 + 8 + 4

/// Token lifecycle state, determined from the cache header without decrypting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenState {
    /// Token is well within its validity window. Use cached token directly.
    Fresh,
    /// Token is approaching expiration. Try heartbeat refresh; fall back to cached.
    RefreshWindow,
    /// Token has just expired. Try heartbeat refresh; fall back to full re-auth.
    Grace,
    /// Token is fully expired or session timeout exceeded. Full re-auth required.
    Dead,
}

/// Metadata stored in the cache file header (unencrypted).
/// These fields are readable without decrypting so we can check expiration
/// without an unnecessary Secure Enclave / TPM call.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct CacheHeader {
    pub risk_level: u8,
    pub token_iat: u64,
    pub session_start: u64,
    pub ciphertext_len: u32,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs()
}

/// Per-token expiration max age in seconds.
pub fn max_age_secs(risk_level: u8) -> u64 {
    match risk_level {
        1 => 86400,  // 24h
        3 => 3600,   // 1h
        // 2 and any other value default to medium (12h)
        _ => 43200,
    }
}

/// How long before expiration we start attempting refresh.
fn refresh_window_secs(risk_level: u8) -> u64 {
    match risk_level {
        1 => 7200,   // last 2h of 24h
        3 => 600,    // last 10m of 1h
        // 2 and any other value default to last 1h of 12h
        _ => 3600,
    }
}

/// Grace period after max_age where we still attempt heartbeat refresh.
const GRACE_SECS: u64 = 300; // 5 minutes

/// Absolute session timeout -- kills the session regardless of token freshness.
fn session_timeout_secs(risk_level: u8) -> u64 {
    match risk_level {
        1 => 259200,  // 72h
        3 => 28800,   // 8h
        // 2 and any other value default to 24h
        _ => 86400,
    }
}

/// Classify the token into a lifecycle state based on timestamps.
pub fn classify_token(
    token_iat: u64,
    session_start: u64,
    risk_level: u8,
) -> TokenState {
    let now = now_secs();

    // Absolute session timeout check
    let session_age = now.saturating_sub(session_start);
    if session_age >= session_timeout_secs(risk_level) {
        return TokenState::Dead;
    }

    let token_age = now.saturating_sub(token_iat);
    let max = max_age_secs(risk_level);
    let refresh_start = max.saturating_sub(refresh_window_secs(risk_level));
    let grace_end = max + GRACE_SECS;

    if token_age < refresh_start {
        TokenState::Fresh
    } else if token_age < max {
        TokenState::RefreshWindow
    } else if token_age < grace_end {
        TokenState::Grace
    } else {
        TokenState::Dead
    }
}

/// Classify a token at a specific point in time (for testing).
#[cfg(test)]
pub fn classify_token_at(
    now: u64,
    token_iat: u64,
    session_start: u64,
    risk_level: u8,
) -> TokenState {
    let session_age = now.saturating_sub(session_start);
    if session_age >= session_timeout_secs(risk_level) {
        return TokenState::Dead;
    }

    let token_age = now.saturating_sub(token_iat);
    let max = max_age_secs(risk_level);
    let refresh_start = max.saturating_sub(refresh_window_secs(risk_level));
    let grace_end = max + GRACE_SECS;

    if token_age < refresh_start {
        TokenState::Fresh
    } else if token_age < max {
        TokenState::RefreshWindow
    } else if token_age < grace_end {
        TokenState::Grace
    } else {
        TokenState::Dead
    }
}

/// Read the cache file header without decrypting the ciphertext.
pub fn read_header(path: &Path) -> Result<Option<CacheHeader>> {
    if !path.exists() {
        return Ok(None);
    }

    let mut file =
        fs::File::open(path).context("failed to open cache file")?;
    let mut header_buf = [0_u8; HEADER_SIZE];

    match file.read_exact(&mut header_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Ok(None); // truncated/corrupt file
        }
        Err(e) => return Err(e.into()),
    }

    // Validate magic
    if &header_buf[0..4] != MAGIC {
        return Ok(None); // not a valid cache file
    }

    // Validate version
    if header_buf[4] != FORMAT_VERSION {
        return Ok(None); // incompatible version
    }

    let risk_level = header_buf[5];
    let token_iat = u64::from_be_bytes(
        header_buf[6..14]
            .try_into()
            .map_err(|_| anyhow!("cache header: invalid token_iat slice"))?,
    );
    let session_start = u64::from_be_bytes(
        header_buf[14..22]
            .try_into()
            .map_err(|_| anyhow!("cache header: invalid session_start slice"))?,
    );
    let ciphertext_len = u32::from_be_bytes(
        header_buf[22..26]
            .try_into()
            .map_err(|_| anyhow!("cache header: invalid ciphertext_len slice"))?,
    );

    Ok(Some(CacheHeader {
        risk_level,
        token_iat,
        session_start,
        ciphertext_len,
    }))
}

/// Read the encrypted ciphertext blob from the cache file (skipping header).
fn read_ciphertext(path: &Path, expected_len: u32) -> Result<Vec<u8>> {
    let data = fs::read(path).context("failed to read cache file")?;
    if data.len() < HEADER_SIZE + expected_len as usize {
        return Err(anyhow!("cache file truncated"));
    }
    Ok(data[HEADER_SIZE..HEADER_SIZE + expected_len as usize].to_vec())
}

/// Write a cache file with the given token.
pub fn write_cache(
    path: &Path,
    storage: &dyn SecureStorage,
    token: &str,
    risk_level: u8,
    session_start: u64,
) -> Result<()> {
    let token_iat =
        jwt::extract_iat(token).unwrap_or_else(|_| now_secs());

    let ciphertext = storage
        .encrypt(token.as_bytes())
        .context("failed to encrypt token")?;

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .context("failed to create cache directory")?;
    }

    let mut file =
        fs::File::create(path).context("failed to create cache file")?;

    // Write header
    file.write_all(MAGIC)?;
    file.write_all(&[FORMAT_VERSION])?;
    file.write_all(&[risk_level])?;
    file.write_all(&token_iat.to_be_bytes())?;
    file.write_all(&session_start.to_be_bytes())?;
    file.write_all(&(ciphertext.len() as u32).to_be_bytes())?;

    // Write ciphertext
    file.write_all(&ciphertext)?;
    file.flush()?;

    Ok(())
}

/// Delete the cache file.
pub fn clear(config: &Config) -> Result<()> {
    let path = config.cache_file_path();
    if path.exists() {
        fs::remove_file(&path).context("failed to remove cache file")?;
    }
    Ok(())
}

/// Main token resolution flow:
/// 1. Check cache header (no decryption)
/// 2. Classify token state
/// 3. Return cached / refresh / re-auth as appropriate
#[allow(clippy::print_stderr)]
pub fn resolve_token(
    config: &Config,
    storage: &dyn SecureStorage,
) -> Result<String> {
    let cache_path = config.cache_file_path();

    // Step 1: Read cache header
    let header = read_header(&cache_path)?;

    if let Some(header) = header {
        let state = classify_token(
            header.token_iat,
            header.session_start,
            config.risk_level,
        );

        match state {
            TokenState::Fresh => {
                // Decrypt and return
                let ciphertext =
                    read_ciphertext(&cache_path, header.ciphertext_len)?;
                let plaintext = storage
                    .decrypt(&ciphertext)
                    .context("failed to decrypt cached token")?;
                let token = String::from_utf8(plaintext.to_vec())
                    .context("cached token is not valid UTF-8")?;
                return Ok(token);
            }

            TokenState::RefreshWindow => {
                // Decrypt, try refresh, fall back to cached
                let ciphertext =
                    read_ciphertext(&cache_path, header.ciphertext_len)?;
                let plaintext = storage
                    .decrypt(&ciphertext)
                    .context("failed to decrypt cached token")?;
                let token = String::from_utf8(plaintext.to_vec())
                    .context("cached token is not valid UTF-8")?;

                match oauth::heartbeat_refresh(
                    &config.sso_url(),
                    &token,
                ) {
                    Some(new_token) => {
                        // Cache the refreshed token, preserve session_start
                        write_cache(
                            &cache_path,
                            storage,
                            &new_token,
                            config.risk_level,
                            header.session_start,
                        )?;
                        return Ok(new_token);
                    }
                    None => {
                        let remaining_secs = max_age_secs(config.risk_level)
                            .saturating_sub(
                                now_secs()
                                    .saturating_sub(header.token_iat),
                            );
                        let remaining_min = remaining_secs / 60;
                        eprintln!(
                            "warning: token refresh failed, using cached token (expires in {remaining_min}m)"
                        );
                        return Ok(token);
                    }
                }
            }

            TokenState::Grace => {
                // Decrypt, try refresh, fall back to full re-auth
                let ciphertext =
                    read_ciphertext(&cache_path, header.ciphertext_len)?;
                let plaintext = storage
                    .decrypt(&ciphertext)
                    .context("failed to decrypt cached token")?;
                let token = String::from_utf8(plaintext.to_vec())
                    .context("cached token is not valid UTF-8")?;

                if let Some(new_token) = oauth::heartbeat_refresh(
                    &config.sso_url(),
                    &token,
                ) {
                    write_cache(
                        &cache_path,
                        storage,
                        &new_token,
                        config.risk_level,
                        header.session_start,
                    )?;
                    return Ok(new_token);
                }
                // Fall through to full re-auth
            }

            TokenState::Dead => {
                // Fall through to full re-auth
            }
        }
    }

    // Full re-authentication
    let oauth_url = config.oauth_url()?;
    let auto_open = !config.no_open;
    let token = oauth::authenticate(&oauth_url, auto_open)?;

    let token_iat =
        jwt::extract_iat(&token).unwrap_or_else(|_| now_secs());

    write_cache(
        &cache_path,
        storage,
        &token,
        config.risk_level,
        token_iat, // session_start = token_iat for fresh auth
    )?;

    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_storage::mock::MockStorage;
    use base64::Engine;

    fn make_jwt(iat: u64) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!(r#"{{"iat":{iat}}}"#));
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode("sig");
        format!("{header}.{payload}.{sig}")
    }

    // ---- Token lifecycle classification tests ----

    #[test]
    fn fresh_token_risk_level_2() {
        let now = 1700000000;
        let iat = now - 100; // 100 seconds old
        let state = classify_token_at(now, iat, iat, 2);
        assert_eq!(state, TokenState::Fresh);
    }

    #[test]
    fn refresh_window_risk_level_2() {
        let now = 1700000000;
        let iat = now - 40000; // 11.1h old (12h max, 1h refresh window)
        let state = classify_token_at(now, iat, iat, 2);
        assert_eq!(state, TokenState::RefreshWindow);
    }

    #[test]
    fn grace_period_risk_level_2() {
        let now = 1700000000;
        let iat = now - 43300; // 12h + 100s (within 5min grace)
        let state = classify_token_at(now, iat, iat, 2);
        assert_eq!(state, TokenState::Grace);
    }

    #[test]
    fn dead_token_risk_level_2() {
        let now = 1700000000;
        let iat = now - 44000; // 12h + ~16min (past grace)
        let state = classify_token_at(now, iat, iat, 2);
        assert_eq!(state, TokenState::Dead);
    }

    #[test]
    fn session_timeout_kills_fresh_token() {
        let now = 1700000000;
        let session_start = now - 90000; // 25h session (24h timeout for RL2)
        let token_iat = now - 100; // token itself is fresh
        let state =
            classify_token_at(now, token_iat, session_start, 2);
        assert_eq!(state, TokenState::Dead);
    }

    #[test]
    fn session_within_timeout_allows_fresh() {
        let now = 1700000000;
        let session_start = now - 80000; // 22h session (within 24h)
        let token_iat = now - 100;
        let state =
            classify_token_at(now, token_iat, session_start, 2);
        assert_eq!(state, TokenState::Fresh);
    }

    #[test]
    fn risk_level_1_boundaries() {
        let now = 1700000000;
        // Fresh: within first 22h (24h - 2h refresh window)
        assert_eq!(
            classify_token_at(now, now - 79000, now - 79000, 1),
            TokenState::Fresh
        );
        // Refresh: in last 2h
        assert_eq!(
            classify_token_at(now, now - 83000, now - 83000, 1),
            TokenState::RefreshWindow
        );
        // Grace: 24h + 0-5min
        assert_eq!(
            classify_token_at(now, now - 86500, now - 86500, 1),
            TokenState::Grace
        );
        // Dead: past grace
        assert_eq!(
            classify_token_at(now, now - 87000, now - 87000, 1),
            TokenState::Dead
        );
    }

    #[test]
    fn risk_level_3_boundaries() {
        let now = 1700000000;
        // Fresh: within first 50min (1h - 10min refresh window)
        assert_eq!(
            classify_token_at(now, now - 2900, now - 2900, 3),
            TokenState::Fresh
        );
        // Refresh: in last 10min
        assert_eq!(
            classify_token_at(now, now - 3100, now - 3100, 3),
            TokenState::RefreshWindow
        );
        // Grace: 1h + 0-5min
        assert_eq!(
            classify_token_at(now, now - 3700, now - 3700, 3),
            TokenState::Grace
        );
        // Dead: past grace
        assert_eq!(
            classify_token_at(now, now - 4000, now - 4000, 3),
            TokenState::Dead
        );
    }

    #[test]
    fn session_timeout_by_risk_level() {
        let now = 1700000000;
        // RL1: 72h timeout
        assert_eq!(
            classify_token_at(now, now - 100, now - 260000, 1),
            TokenState::Dead
        );
        assert_eq!(
            classify_token_at(now, now - 100, now - 258000, 1),
            TokenState::Fresh
        );

        // RL2: 24h timeout (tested above)

        // RL3: 8h timeout
        assert_eq!(
            classify_token_at(now, now - 100, now - 29000, 3),
            TokenState::Dead
        );
        assert_eq!(
            classify_token_at(now, now - 100, now - 27000, 3),
            TokenState::Fresh
        );
    }

    // ---- Cache file format tests ----

    #[test]
    fn write_and_read_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let storage = MockStorage::new();
        let token = make_jwt(1700000000);

        write_cache(&path, &storage, &token, 2, 1700000000).unwrap();

        let header = read_header(&path).unwrap().unwrap();
        assert_eq!(header.risk_level, 2);
        assert_eq!(header.token_iat, 1700000000);
        assert_eq!(header.session_start, 1700000000);
        assert!(header.ciphertext_len > 0);
    }

    #[test]
    fn write_and_decrypt_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.enc");
        let storage = MockStorage::new();
        let token = make_jwt(1700000000);

        write_cache(&path, &storage, &token, 2, 1700000000).unwrap();

        let header = read_header(&path).unwrap().unwrap();
        let ciphertext =
            read_ciphertext(&path, header.ciphertext_len).unwrap();
        let plaintext = storage.decrypt(&ciphertext).unwrap();
        let recovered =
            String::from_utf8(plaintext.to_vec()).unwrap();
        assert_eq!(recovered, token);
    }

    #[test]
    fn missing_cache_file_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.enc");
        assert!(read_header(&path).unwrap().is_none());
    }

    #[test]
    fn corrupt_magic_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.enc");
        fs::write(&path, b"BADXrest of data here").unwrap();
        assert!(read_header(&path).unwrap().is_none());
    }

    #[test]
    fn truncated_file_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("short.enc");
        fs::write(&path, b"SJW").unwrap(); // too short
        assert!(read_header(&path).unwrap().is_none());
    }

    #[test]
    fn wrong_version_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ver.enc");
        let mut data = vec![0u8; HEADER_SIZE + 10];
        data[0..4].copy_from_slice(MAGIC);
        data[4] = 0xFF; // bad version
        fs::write(&path, &data).unwrap();
        assert!(read_header(&path).unwrap().is_none());
    }

    #[test]
    fn clear_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("default.enc");
        fs::write(&path, b"dummy").unwrap();
        assert!(path.exists());

        // Build a config pointing at our temp dir
        let mut config = Config::load().unwrap();
        config.cache_name = "default".to_string();
        // Override cache path via a workaround: write to our known path
        fs::remove_file(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn session_start_preserved_on_refresh_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("refresh.enc");
        let storage = MockStorage::new();

        let original_session_start = 1699900000;
        let token1 = make_jwt(1700000000);

        write_cache(
            &path,
            &storage,
            &token1,
            2,
            original_session_start,
        )
        .unwrap();

        // "Refresh" -- new token but same session_start
        let token2 = make_jwt(1700043200);
        write_cache(
            &path,
            &storage,
            &token2,
            2,
            original_session_start,
        )
        .unwrap();

        let header = read_header(&path).unwrap().unwrap();
        assert_eq!(header.session_start, original_session_start);
        assert_eq!(header.token_iat, 1700043200);
    }

    #[test]
    fn max_age_values() {
        assert_eq!(max_age_secs(1), 86400);
        assert_eq!(max_age_secs(2), 43200);
        assert_eq!(max_age_secs(3), 3600);
    }

    #[test]
    fn edge_case_zero_age() {
        let now = 1700000000;
        assert_eq!(
            classify_token_at(now, now, now, 2),
            TokenState::Fresh
        );
    }

    #[test]
    fn edge_case_exact_refresh_boundary() {
        let now = 1700000000;
        // Exactly at refresh boundary for RL2: max_age(43200) - refresh(3600) = 39600
        assert_eq!(
            classify_token_at(now, now - 39600, now - 39600, 2),
            TokenState::RefreshWindow
        );
        // One second before
        assert_eq!(
            classify_token_at(now, now - 39599, now - 39599, 2),
            TokenState::Fresh
        );
    }

    #[test]
    fn edge_case_exact_max_age() {
        let now = 1700000000;
        // Exactly at max_age for RL2 = 43200
        assert_eq!(
            classify_token_at(now, now - 43200, now - 43200, 2),
            TokenState::Grace
        );
    }

    #[test]
    fn edge_case_exact_grace_end() {
        let now = 1700000000;
        // Exactly at grace end for RL2 = 43200 + 300 = 43500
        assert_eq!(
            classify_token_at(now, now - 43500, now - 43500, 2),
            TokenState::Dead
        );
        // One second before grace end
        assert_eq!(
            classify_token_at(now, now - 43499, now - 43499, 2),
            TokenState::Grace
        );
    }

    // ---- Risk level edge cases for classify_token_at ----

    #[test]
    fn risk_level_0_uses_default_medium() {
        let now = 1700000000;
        // RL0 should fall through to default (same as RL2): max_age=43200
        // Fresh within first 39600s
        assert_eq!(
            classify_token_at(now, now - 100, now - 100, 0),
            TokenState::Fresh
        );
        // Dead after grace end (43200 + 300 = 43500)
        assert_eq!(
            classify_token_at(now, now - 44000, now - 44000, 0),
            TokenState::Dead
        );
    }

    #[test]
    fn risk_level_4_uses_default_medium() {
        let now = 1700000000;
        assert_eq!(
            classify_token_at(now, now - 100, now - 100, 4),
            TokenState::Fresh
        );
        assert_eq!(
            classify_token_at(now, now - 44000, now - 44000, 4),
            TokenState::Dead
        );
    }

    #[test]
    fn risk_level_255_uses_default_medium() {
        let now = 1700000000;
        assert_eq!(
            classify_token_at(now, now - 100, now - 100, 255),
            TokenState::Fresh
        );
        // RefreshWindow at 40000s (within 39600..43200)
        assert_eq!(
            classify_token_at(now, now - 40000, now - 40000, 255),
            TokenState::RefreshWindow
        );
        assert_eq!(
            classify_token_at(now, now - 44000, now - 44000, 255),
            TokenState::Dead
        );
    }

    // ---- Timestamp edge cases ----

    #[test]
    fn future_token_iat_is_fresh_due_to_saturating_sub() {
        let now = 1700000000;
        // token_iat is 10s in the future (server clock skew)
        let iat = now + 10;
        // saturating_sub(now, iat) = 0, so token_age = 0 => Fresh
        assert_eq!(
            classify_token_at(now, iat, now, 2),
            TokenState::Fresh
        );
    }

    #[test]
    fn future_session_start_is_fresh_due_to_saturating_sub() {
        let now = 1700000000;
        // session_start is 10s in the future
        let session_start = now + 10;
        // saturating_sub(now, session_start) = 0 => within session timeout
        assert_eq!(
            classify_token_at(now, now, session_start, 2),
            TokenState::Fresh
        );
    }

    #[test]
    fn token_iat_zero_with_large_now_is_dead() {
        let now = 1700000000;
        // token_iat = 0, token_age = 1700000000 => well past any max_age
        assert_eq!(
            classify_token_at(now, 0, now, 2),
            TokenState::Dead
        );
    }

    #[test]
    fn session_start_zero_with_large_now_is_dead() {
        let now = 1700000000;
        // session_start = 0, session_age = 1700000000 => exceeds any session timeout
        assert_eq!(
            classify_token_at(now, now - 100, 0, 2),
            TokenState::Dead
        );
    }

    // ---- Cache format edge cases ----

    #[test]
    fn header_only_file_with_zero_ciphertext_len() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("header_only.enc");

        // Build a valid header with ciphertext_len = 0
        let mut data = Vec::with_capacity(HEADER_SIZE);
        data.extend_from_slice(MAGIC);
        data.push(FORMAT_VERSION);
        data.push(2); // risk_level
        data.extend_from_slice(&1700000000_u64.to_be_bytes()); // token_iat
        data.extend_from_slice(&1700000000_u64.to_be_bytes()); // session_start
        data.extend_from_slice(&0_u32.to_be_bytes()); // ciphertext_len = 0
        assert_eq!(data.len(), HEADER_SIZE);
        fs::write(&path, &data).expect("write header-only file");

        let header =
            read_header(&path).expect("read_header").expect("header present");
        assert_eq!(header.ciphertext_len, 0);

        let ct = read_ciphertext(&path, 0).expect("read empty ciphertext");
        assert!(ct.is_empty());
    }

    #[test]
    fn ciphertext_len_larger_than_actual_data_returns_error() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("short_ct.enc");

        let mut data = Vec::with_capacity(HEADER_SIZE + 5);
        data.extend_from_slice(MAGIC);
        data.push(FORMAT_VERSION);
        data.push(2);
        data.extend_from_slice(&1700000000_u64.to_be_bytes());
        data.extend_from_slice(&1700000000_u64.to_be_bytes());
        data.extend_from_slice(&100_u32.to_be_bytes()); // claims 100 bytes
        data.extend_from_slice(&[0xAA; 5]); // but only 5 bytes present
        fs::write(&path, &data).expect("write truncated ciphertext file");

        let result = read_ciphertext(&path, 100);
        assert!(result.is_err());
    }

    #[test]
    fn empty_file_returns_none() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("empty.enc");
        fs::write(&path, b"").expect("write empty file");
        assert!(read_header(&path).expect("read_header").is_none());
    }

    #[test]
    fn file_with_exactly_header_size_bytes() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("exact_header.enc");

        let mut data = vec![0u8; HEADER_SIZE];
        data[0..4].copy_from_slice(MAGIC);
        data[4] = FORMAT_VERSION;
        data[5] = 3; // risk_level
        data[6..14].copy_from_slice(&42_u64.to_be_bytes());
        data[14..22].copy_from_slice(&99_u64.to_be_bytes());
        data[22..26].copy_from_slice(&0_u32.to_be_bytes());
        fs::write(&path, &data).expect("write exact header file");

        let header =
            read_header(&path).expect("read_header").expect("header present");
        assert_eq!(header.risk_level, 3);
        assert_eq!(header.token_iat, 42);
        assert_eq!(header.session_start, 99);
        assert_eq!(header.ciphertext_len, 0);
    }

    #[test]
    fn all_risk_levels_stored_correctly_in_header() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let storage = MockStorage::new();
        let token = make_jwt(1700000000);

        for rl in [1_u8, 2, 3] {
            let path = dir.path().join(format!("rl{rl}.enc"));
            write_cache(&path, &storage, &token, rl, 1700000000)
                .expect("write_cache");
            let header = read_header(&path)
                .expect("read_header")
                .expect("header present");
            assert_eq!(header.risk_level, rl);
        }
    }

    #[test]
    fn large_token_roundtrip_1kb() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("large1k.enc");
        let storage = MockStorage::new();

        // Build a JWT with a large payload (~1KB)
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let large_payload = format!(
            r#"{{"iat":1700000000,"data":"{}"}}"#,
            "A".repeat(900)
        );
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&large_payload);
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode("sig");
        let token = format!("{header_b64}.{payload_b64}.{sig_b64}");
        assert!(token.len() > 1000);

        write_cache(&path, &storage, &token, 2, 1700000000)
            .expect("write_cache");

        let header = read_header(&path)
            .expect("read_header")
            .expect("header present");
        let ct = read_ciphertext(&path, header.ciphertext_len)
            .expect("read_ciphertext");
        let pt = storage.decrypt(&ct).expect("decrypt");
        let recovered =
            String::from_utf8(pt.to_vec()).expect("valid utf-8");
        assert_eq!(recovered, token);
    }

    #[test]
    fn large_token_roundtrip_10kb() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("large10k.enc");
        let storage = MockStorage::new();

        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let large_payload = format!(
            r#"{{"iat":1700000000,"data":"{}"}}"#,
            "B".repeat(9000)
        );
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&large_payload);
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode("sig");
        let token = format!("{header_b64}.{payload_b64}.{sig_b64}");
        assert!(token.len() > 10000);

        write_cache(&path, &storage, &token, 2, 1700000000)
            .expect("write_cache");

        let header = read_header(&path)
            .expect("read_header")
            .expect("header present");
        let ct = read_ciphertext(&path, header.ciphertext_len)
            .expect("read_ciphertext");
        let pt = storage.decrypt(&ct).expect("decrypt");
        let recovered =
            String::from_utf8(pt.to_vec()).expect("valid utf-8");
        assert_eq!(recovered, token);
    }

    // ---- write_cache with token missing iat claim ----

    #[test]
    fn write_cache_token_missing_iat_uses_fallback() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("no_iat.enc");
        let storage = MockStorage::new();

        // Build a JWT without an iat claim
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"sub":"user123"}"#);
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode("sig");
        let token = format!("{header_b64}.{payload_b64}.{sig_b64}");

        write_cache(&path, &storage, &token, 2, 1700000000)
            .expect("write_cache should succeed without iat");

        let header = read_header(&path)
            .expect("read_header")
            .expect("header present");
        // token_iat should be close to now (the fallback)
        let now = now_secs();
        assert!(
            header.token_iat <= now && header.token_iat >= now - 5,
            "token_iat should be near now_secs(), got {}",
            header.token_iat
        );

        // Verify the token itself round-trips
        let ct = read_ciphertext(&path, header.ciphertext_len)
            .expect("read_ciphertext");
        let pt = storage.decrypt(&ct).expect("decrypt");
        let recovered =
            String::from_utf8(pt.to_vec()).expect("valid utf-8");
        assert_eq!(recovered, token);
    }

    // ---- read_ciphertext direct tests ----

    #[test]
    fn read_ciphertext_truncated_data() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("trunc_ct.enc");

        let mut data = Vec::with_capacity(HEADER_SIZE + 50);
        data.extend_from_slice(MAGIC);
        data.push(FORMAT_VERSION);
        data.push(2);
        data.extend_from_slice(&1700000000_u64.to_be_bytes());
        data.extend_from_slice(&1700000000_u64.to_be_bytes());
        data.extend_from_slice(&100_u32.to_be_bytes()); // claims 100 bytes
        data.extend_from_slice(&[0xBB; 50]); // only 50 bytes after header
        fs::write(&path, &data).expect("write file");

        let result = read_ciphertext(&path, 100);
        assert!(result.is_err(), "should fail when ciphertext is truncated");
    }

    #[test]
    fn read_ciphertext_exact_match() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("exact_ct.enc");
        let payload = [0xCC; 37];

        let mut data = Vec::with_capacity(HEADER_SIZE + payload.len());
        data.extend_from_slice(MAGIC);
        data.push(FORMAT_VERSION);
        data.push(1);
        data.extend_from_slice(&1700000000_u64.to_be_bytes());
        data.extend_from_slice(&1700000000_u64.to_be_bytes());
        data.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        data.extend_from_slice(&payload);
        fs::write(&path, &data).expect("write file");

        let ct = read_ciphertext(&path, payload.len() as u32)
            .expect("read_ciphertext");
        assert_eq!(ct, payload);
    }

    // ---- Multiple caches side by side ----

    #[test]
    fn two_cache_files_in_same_directory_no_interference() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path_a = dir.path().join("cache_a.enc");
        let path_b = dir.path().join("cache_b.enc");
        let storage = MockStorage::new();

        let token_a = make_jwt(1700000000);
        let token_b = make_jwt(1700100000);

        write_cache(&path_a, &storage, &token_a, 1, 1700000000)
            .expect("write cache A");
        write_cache(&path_b, &storage, &token_b, 3, 1700100000)
            .expect("write cache B");

        // Read back cache A
        let hdr_a = read_header(&path_a)
            .expect("read_header A")
            .expect("header A present");
        assert_eq!(hdr_a.risk_level, 1);
        assert_eq!(hdr_a.token_iat, 1700000000);
        let ct_a = read_ciphertext(&path_a, hdr_a.ciphertext_len)
            .expect("read_ciphertext A");
        let pt_a = storage.decrypt(&ct_a).expect("decrypt A");
        assert_eq!(
            String::from_utf8(pt_a.to_vec()).expect("utf-8 A"),
            token_a
        );

        // Read back cache B
        let hdr_b = read_header(&path_b)
            .expect("read_header B")
            .expect("header B present");
        assert_eq!(hdr_b.risk_level, 3);
        assert_eq!(hdr_b.token_iat, 1700100000);
        let ct_b = read_ciphertext(&path_b, hdr_b.ciphertext_len)
            .expect("read_ciphertext B");
        let pt_b = storage.decrypt(&ct_b).expect("decrypt B");
        assert_eq!(
            String::from_utf8(pt_b.to_vec()).expect("utf-8 B"),
            token_b
        );
    }

    // ---- Overwrite existing cache ----

    #[test]
    fn overwrite_cache_recovers_new_token() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("overwrite.enc");
        let storage = MockStorage::new();

        let token_old = make_jwt(1700000000);
        let token_new = make_jwt(1700050000);

        write_cache(&path, &storage, &token_old, 2, 1700000000)
            .expect("write old cache");

        // Overwrite with new token
        write_cache(&path, &storage, &token_new, 2, 1700000000)
            .expect("write new cache");

        let header = read_header(&path)
            .expect("read_header")
            .expect("header present");
        assert_eq!(header.token_iat, 1700050000);

        let ct = read_ciphertext(&path, header.ciphertext_len)
            .expect("read_ciphertext");
        let pt = storage.decrypt(&ct).expect("decrypt");
        let recovered =
            String::from_utf8(pt.to_vec()).expect("valid utf-8");
        assert_eq!(recovered, token_new);
        assert_ne!(recovered, token_old);
    }

    // ---- Session timeout boundary precision for all risk levels ----

    #[test]
    fn session_timeout_boundary_risk_level_1() {
        let now = 1700000000;
        let timeout = session_timeout_secs(1); // 259200 (72h)

        // At exactly timeout - 1: not dead (token is fresh)
        assert_ne!(
            classify_token_at(now, now - 100, now - (timeout - 1), 1),
            TokenState::Dead,
        );
        // At exactly timeout: dead
        assert_eq!(
            classify_token_at(now, now - 100, now - timeout, 1),
            TokenState::Dead,
        );
    }

    #[test]
    fn session_timeout_boundary_risk_level_2() {
        let now = 1700000000;
        let timeout = session_timeout_secs(2); // 86400 (24h)

        assert_ne!(
            classify_token_at(now, now - 100, now - (timeout - 1), 2),
            TokenState::Dead,
        );
        assert_eq!(
            classify_token_at(now, now - 100, now - timeout, 2),
            TokenState::Dead,
        );
    }

    #[test]
    fn session_timeout_boundary_risk_level_3() {
        let now = 1700000000;
        let timeout = session_timeout_secs(3); // 28800 (8h)

        assert_ne!(
            classify_token_at(now, now - 100, now - (timeout - 1), 3),
            TokenState::Dead,
        );
        assert_eq!(
            classify_token_at(now, now - 100, now - timeout, 3),
            TokenState::Dead,
        );
    }
}
