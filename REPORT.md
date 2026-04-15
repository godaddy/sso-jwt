# Codex Change Audit Report

**Date:** 2026-04-15
**Reviewer:** Claude Opus 4.6
**Scope:** All commits since 2026-04-13 18:00 (commit `4705e2f` to `e6bac8f`)
**Commits reviewed:** 17 non-merge commits across 6 PRs (#6–#12)
**Files changed:** 17 files, +2,492 / -761 lines

## Executive Summary

Codex made substantial changes across all four workspace crates, focused on security hardening, cache correctness, and test stabilization. The majority of changes are well-motivated and correctly implemented. The work addressed real security vulnerabilities (path traversal in cache naming, cleartext HTTP endpoints, missing URL encoding in OAuth requests) and real correctness issues (cache path aliasing, unvalidated risk levels, shell injection in `git archive`).

However, the changes introduced **several new defects** and **quality regressions** that need attention.

---

## Findings by Severity

### DEFECTS (bugs or incorrect behavior)

#### D1. Flaky tests without `--test-threads=1` (sso-jwt-lib)
**Severity:** Medium
**Location:** `sso-jwt-lib/src/config.rs` and `sso-jwt-lib/src/cache.rs` test modules

Multiple tests use `env::set_var`/`env::remove_var` which is inherently thread-unsafe. The `TEST_ENV_MUTEX` synchronization was added but not applied consistently to all tests. Confirmed flaky failures:
- `config::tests::config_dir_ends_in_sso_jwt` (line 821) — does not acquire `TEST_ENV_MUTEX`
- `config::tests::safe_legacy_cache_path_remains_available_for_migration` — fails intermittently under parallel execution

The CI workaround (`--test-threads=1` in `ci.yml`) masks the problem. Tests pass with serialization but the underlying env var races remain.

#### D2. `index.d.ts` missing `tokenUrl` field (sso-jwt-napi)
**Severity:** Medium
**Location:** `sso-jwt-napi/index.d.ts`

The Rust NAPI struct (`JwtOptions` in `lib.rs:14`) has `token_url: Option<String>` and `convert_options()` maps it correctly, but the TypeScript definition at `index.d.ts` omits `tokenUrl`. Node.js callers using TypeScript cannot pass this option. **`NEW_DEFECTS.md` line 29 falsely claims this was fixed.**

#### D3. `ensure_key` silently accepts mismatched policy when metadata file is missing (sso-jwt-tpm-bridge)
**Severity:** Medium
**Location:** `sso-jwt-tpm-bridge/src/tpm.rs`, line 44

When a TPM key exists but has no `.meta` sidecar file (pre-migration keys, or metadata accidentally deleted), `ensure_key` returns `Ok(())` and reuses the existing key regardless of the requested `AccessPolicy`. A key created with `AccessPolicy::None` could be reused when `AccessPolicy::BiometricOnly` is requested. The safe behavior would be to delete and regenerate when metadata is absent, since the policy cannot be verified.

#### D4. Unused `serde_json` dependency (sso-jwt)
**Severity:** Low
**Location:** `sso-jwt/Cargo.toml:14`

`serde_json = "1"` is listed as a dependency but never imported anywhere in the `sso-jwt` crate. Adds unnecessary compile-time cost.

#### D5. `is_none_or()` requires Rust 1.82+ (sso-jwt-lib)
**Severity:** Low
**Location:** `sso-jwt-lib/src/cache.rs:308`

`Option::is_none_or()` was stabilized in Rust 1.82 (Oct 2024). The documented MSRV in CLAUDE.md is Rust 1.75+. If the MSRV has not been formally bumped, this will break on older toolchains. Current local toolchain (1.94.1) is unaffected.

---

### DESIGN CONCERNS (not broken, but questionable)

#### C1. `BridgeRequestCompat` duplicates upstream `BridgeRequest` (sso-jwt-tpm-bridge)
**Location:** `sso-jwt-tpm-bridge/src/main.rs:22-56`

`BridgeRequestCompat` / `BridgeParamsCompat` have identical fields to `enclaveapp_bridge::BridgeRequest` / `BridgeParams`. The only additions are: `#[serde(default)]` on the `params` field (upstream requires it), and `app_name()`/`key_label()` helper methods that substitute defaults for empty strings.

The type diverges from upstream in one behavioral way: a JSON payload with no `params` key will deserialize successfully to defaults via `BridgeRequestCompat` but will fail with the upstream `BridgeRequest`. This backward-compatibility intent is reasonable, but having a parallel type that must be manually kept in sync is a maintenance risk. `BridgeResponse` is still imported from upstream, creating an asymmetry.

#### C2. `"destroy"` is now a breaking behavioral change (sso-jwt-tpm-bridge)
**Location:** `sso-jwt-tpm-bridge/src/main.rs:107-120`

The old `"destroy"` method simply cleared in-memory state and always returned success. The new implementation calls `TpmStorage::delete()`, which can fail if the TPM is unavailable or the key doesn't exist. Legacy clients sending `"destroy"` will now see errors in cases that previously succeeded silently. Additionally, if `delete()` fails, the in-memory `*storage` is NOT set to `None`, leaving the bridge in a potentially stale state.

#### C3. `--test-threads=1` is a blunt CI fix
**Location:** `.github/workflows/ci.yml`

Forces the entire workspace test suite to run serially. For this repo's size (~235 tests) the performance impact is small, but the right fix is to either use `serial_test` crate on env-mutating tests or consolidate env manipulation behind a shared mutex that all tests acquire.

#### C4. `NEW_DEFECTS.md` should not be in the repo
**Location:** `NEW_DEFECTS.md`

This is a self-described "resolved-status record" from an AI review tool. It contains at least one false claim (D2 above). Defect tracking belongs in issues/PRs, not committed markdown files. The file itself suggests it can be deleted (line 50).

---

### INFORMATION LOSS (documentation regressions)

#### L1. `DESIGN.md` rewritten from spec to overview
The original `DESIGN.md` was a proper technical specification containing:
- Binary cache format spec (byte offsets, magic bytes, field layout)
- Token lifecycle state machine (Fresh/Refresh/Grace/Dead) with behavioral descriptions
- OAuth Device Code flow sequence diagram
- Risk-level expiration tables with concrete values
- WSL bridge architecture details
- Configuration precedence documentation

The rewrite is a high-level overview that largely duplicates `README.md`. The detailed specification content is now documented nowhere in the repo.

#### L2. Node.js usage documentation removed from `README.md`
The old `README.md` had a Node.js usage section with a link to the NAPI crate. The new README mentions "supports both CLI and Node.js consumers" but provides no usage example or link. The NAPI README's options table also omits `tokenUrl` and `clientId`.

#### L3. Token lifecycle tables removed from all docs
The Fresh/Refresh/Grace/Dead state machine and risk-level expiration tables (which risk level gets what max-age, refresh window, and session timeout) were removed from both `DESIGN.md` and `README.md`. This information is useful for users and operators and isn't easily derived from reading the code.

---

### WHAT WAS DONE WELL

#### Security Hardening
- **Cache path encoding** (`config.rs:58-84`): New `~XX` percent-encoding scheme eliminates path traversal and aliasing vulnerabilities. The old `replace(['/', '\\'], "").replace("..", "")` approach was genuinely unsafe.
- **HTTPS-only endpoint validation** (`config.rs:100-120`, `cli.rs:238-239`): OAuth, token, and heartbeat URLs now reject `http://`. Correctly prevents credential leakage over cleartext.
- **Shell injection surface removed** (`cli.rs`): The `git archive --remote=... | tar -xO` strategy that used `sh -c` with unsanitized input was removed entirely.
- **Pinned GitHub refs** (`cli.rs:404-443`): `--from-github` now requires `owner/repo@ref/path` instead of using `HEAD`, preventing TOCTOU on remote config fetches.
- **Atomic file writes** (`cache.rs:264-276`, `config.rs:421-429`): Cache and config files are now written atomically with restricted Unix permissions.

#### Correctness Fixes
- **OAuth form encoding** (`oauth.rs:44, 94-98`): `.form()` replaces manual `.body(format!(...))`, fixing URL-encoding bugs where `client_id` with special chars would produce malformed requests.
- **`format_user_code` generalization** (`oauth.rs:127-135`): No longer silently truncates codes longer than 8 characters.
- **Risk level normalization** (`cache.rs:51-60`): Invalid values clamped to 2; `effective_cached_risk_level` prevents config downgrades from weakening security on cached tokens.
- **`--clear` resilience** (`cli.rs:142-152`): Now uses `load_for_clear()` so malformed config files don't prevent cache clearing.
- **NAPI risk_level validation** (`napi/lib.rs:49-54`): Out-of-range values now error instead of silently truncating via `as u8`.

#### Network Hardening
- **30-second HTTP timeout** and **64KB response size limit** on remote config fetches.
- **`gh` CLI hardening**: `stdin(Stdio::null())`, `GH_PROMPT_DISABLED=1`, timeout enforcement via reader thread + `mpsc::recv_timeout`.
- **`$BROWSER` parsing via `shell_words`**: Properly handles `BROWSER="firefox --private-window"`.

#### Test Coverage
Extensive new tests were added across all crates:
- `sso-jwt-lib`: ~30 new tests covering cache encoding, legacy migration, HTTPS validation, risk level clamping, form encoding, user code formatting
- `sso-jwt`: 7 new tests for timeout, size limits, HTTP rejection, ref parsing, `--clear` resilience
- `sso-jwt-tpm-bridge`: 3 new tests for `ensure_key` policy enforcement
- `sso-jwt-napi`: 2 new tests for risk level validation

---

## Test Results

| Crate | With `--test-threads=1` | Without (parallel) |
|-------|------------------------|--------------------|
| sso-jwt-lib | 157 pass, 0 fail | Flaky (1 failure per run, varies) |
| sso-jwt | 75 pass, 0 fail | 75 pass, 0 fail |
| sso-jwt-tpm-bridge | 25 pass, 0 fail | 25 pass, 0 fail |
| sso-jwt-napi | 2 pass, 0 fail | 2 pass, 0 fail |

`cargo clippy --workspace --all-targets -- -D warnings`: **Clean, zero warnings.**

---

## Recommended Actions

| Priority | Action |
|----------|--------|
| **High** | Fix `index.d.ts` — add `tokenUrl?: string` field (D2) |
| **High** | Fix `ensure_key` to regenerate key when `.meta` is missing rather than assuming policy matches (D3) |
| **Medium** | Fix flaky tests — add `TEST_ENV_MUTEX` to `config_dir_ends_in_sso_jwt` and any other tests that read env vars without locking (D1) |
| **Medium** | Restore token lifecycle / cache format documentation to `DESIGN.md` (L1, L3) |
| **Low** | Remove unused `serde_json` from `sso-jwt/Cargo.toml` (D4) |
| **Low** | Delete `NEW_DEFECTS.md` — it's noise with a false claim (C4) |
| **Low** | Evaluate replacing `BridgeRequestCompat` with upstream `BridgeRequest` + default logic in `handle_request` (C1) |
| **Low** | Confirm MSRV bump to 1.82+ or replace `is_none_or()` (D5) |

---

## Conclusion

The Codex changes represent a net positive for the codebase — they fix real security vulnerabilities, improve correctness in edge cases, and add substantial test coverage. The security hardening work (cache path encoding, HTTPS enforcement, atomic writes, shell injection removal) is particularly well done.

The main concerns are: a false "resolved" claim on a real TypeScript type bug, a security gap in TPM key policy enforcement when metadata is missing, flaky test infrastructure, and significant documentation regression where detailed technical specifications were replaced with high-level overviews.
