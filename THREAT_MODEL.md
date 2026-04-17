# Threat Model: sso-jwt

## Assets

| Asset | Description | Sensitivity |
|---|---|---|
| SSO JWT | Authentication token granting access to internal services | High -- allows impersonation of the authenticated user |
| Secure Enclave / TPM private key | Hardware-bound P-256 key used to encrypt cached JWTs | Critical -- compromise enables offline cache decryption |
| Encrypted cache file | ECIES-encrypted JWT stored at `~/.config/sso-jwt/<name>.enc` | Medium -- useless without the hardware key |
| Okta session | User's active Okta session used during OAuth Device Code flow | High -- session hijacking enables token theft |
| OAuth device code | Temporary code used during the Device Code flow | Low -- short-lived (10 minutes), single-use |
| Configuration file | TOML file with environment, risk level, biometric preferences | Low -- no secrets, controls behavior |

## Trust Boundaries

```
+-------------------------------------------------------------------+
| User's Machine                                                     |
|                                                                    |
|  +-----------------+    +----------------+    +-----------------+  |
|  | Shell process   |    | sso-jwt binary |    | Secure Enclave  |  |
|  | (bash/zsh)      |<-->| (Rust process) |<-->| / TPM           |  |
|  +-----------------+    +-------+--------+    +-----------------+  |
|         |                       |                                  |
|         |  $(sso-jwt)           |  HTTPS                          |
|         |  stdout capture       |                                  |
|         v                       v                                  |
|  +-----------------+    +----------------+                        |
|  | Child process   |    | SSO Webservice |  <-- Trust boundary    |
|  | (terraform etc) |    | (Okta/SAML)    |                        |
|  +-----------------+    +----------------+                        |
+-------------------------------------------------------------------+
```

**Trust boundaries:**
1. Between sso-jwt process and the hardware security module (SE/TPM).
2. Between sso-jwt process and the SSO webservice (HTTPS).
3. Between sso-jwt process and the consuming child process (env var handoff).
4. Between the user's machine and an attacker's access point (disk, network, physical).

## Threats and Mitigations

### T1: Plaintext token on disk

**Threat:** An attacker with read access to the user's home directory reads cached JWTs from plaintext files.

**Previous state:** The Node.js `ssojwt` writes JWTs as plaintext to `~/.cache/sso-jwt/<cacheName>`.

**Mitigation:** Cached JWTs are encrypted with ECIES using a P-256 key pair generated in the Secure Enclave (macOS) or TPM 2.0 (Windows). The private key never leaves the hardware. A stolen `.enc` file is an opaque ciphertext blob.

**Residual risk:** None for the cached token. The token briefly exists in process memory as plaintext.

### T2: Cross-machine replay of stolen cache

**Threat:** An attacker copies the `.enc` cache file to another machine and decrypts it.

**Mitigation:** The encryption key is hardware-bound (Secure Enclave / TPM). It is non-exportable and tied to the physical device. The ciphertext can only be decrypted on the machine that created it.

**Residual risk:** None. The hardware provides this guarantee.

### T3: Ambient environment variable exposure

**Threat:** A developer runs `export COMPANY_JWT=$(ssojwt)`, persisting the JWT in the shell's environment. Every subsequent child process inherits it, and it's visible via `ps eww`.

**Mitigation:**
- Shell integration (`eval "$(sso-jwt shell-init)"`) installs a wrapper function that detects `export` context and refuses to emit the JWT.
- The `exec` subcommand (`sso-jwt exec -- terraform apply`) injects the JWT directly into the child process's environment without ever writing to stdout.
- Documentation and error messages guide users toward safe patterns.

**Residual risk:** The shell wrapper is best-effort -- indirect invocations, scripts, or exotic shell constructs may bypass it. Users can still manually capture and export stdout. The `exec` mode is the strongest mitigation.

### T4: Process memory extraction

**Threat:** An attacker with access to the running sso-jwt process (or the consuming child process) reads the JWT from memory.

**Mitigation:**
- JWT plaintext is held in `Zeroizing<Vec<u8>>` (from the `zeroize` crate), which overwrites the buffer with zeros on drop.
- The window of exposure is minimized: the token exists in plaintext only during the decrypt-to-output path.

**Residual risk:** Between decryption and output, the token is in process memory. A root-level attacker can dump process memory during this window. This is inherent to any credential passing scheme.

### T5: Root/admin access on active session

**Threat:** An attacker with root access on the user's machine, while the user is logged in, calls the Secure Enclave / TPM APIs to decrypt the cache.

**Mitigation:**
- The `--biometric` flag requires Touch ID / Windows Hello for each decryption, adding a physical-presence check that root alone cannot satisfy.
- Without biometric: the SE/TPM key is accessible to any process running as the user when the device is unlocked. This is a deliberate tradeoff for usability.

**Residual risk:** Root can install keyloggers, modify the binary, or intercept the token in other ways. Hardware security modules protect against offline attacks, not against a fully compromised running system.

### T6: OAuth Device Code phishing

**Threat:** An attacker displays a fake user code to trick the user into authorizing the attacker's device code.

**Mitigation:** This is inherent to the Device Code flow (RFC 8628). The webservice mitigates it by:
- Short-lived device codes (10-minute TTL).
- User codes displayed as `XXXX-XXXX` for verification.
- The authorization page is on a trusted SSO domain with Okta MFA.

**Residual risk:** A user who doesn't verify the code could authorize an attacker's session. This is a social engineering attack, not a technical one.

### T7: Network interception (MitM)

**Threat:** An attacker intercepts HTTPS traffic between sso-jwt and the SSO webservice.

**Mitigation:**
- All connections use HTTPS with rustls (TLS 1.2/1.3).
- The `reqwest` client uses the `webpki-roots` certificate bundle, not the system trust store, reducing the risk of CA compromise.
- Certificate pinning is not implemented (would complicate certificate rotation).

**Residual risk:** A compromised CA could issue fraudulent certificates. This is a general TLS risk, not specific to sso-jwt.

### T8: Stale token / infinite refresh chain

**Threat:** Reactive refresh-window heartbeat keeps a session alive indefinitely, creating unbounded credential exposure. (Refresh is reactive within `RefreshWindow`/`Grace`, not a background daemon.)

**Mitigation:** Absolute session timeout prevents indefinite refresh:

| Risk Level | Session Timeout |
|---|---|
| 1 (low) | 72 hours |
| 2 (medium) | 24 hours |
| 3 (high) | 8 hours |

The `session_start` timestamp is set when a full Device Code authentication occurs and never updated by heartbeat refresh. Once the session timeout is exceeded, the token is classified as `Dead` and full re-authentication is required.

**Residual risk:** Within the session timeout window, the token is refreshable. For risk level 1, this is up to 72 hours. Organizations requiring shorter windows should use risk level 3.

### T9: Cache file tampering

**Threat:** An attacker modifies the `.enc` file header (risk level, timestamps) to extend token validity.

**Mitigation:**
- The header is unencrypted for performance, but the ECIES ciphertext includes an AES-GCM authentication tag. Tampering with the ciphertext causes decryption failure.
- Tampering with the header timestamps could cause sso-jwt to serve a stale token that the server would then reject. This is a denial-of-service at worst.
- Setting a lower risk level in the header does not grant more access -- it only affects client-side caching behavior.

**Residual risk:** Header tampering can extend client-side caching but cannot create tokens. The server enforces its own expiration independently.

### T10: WSL bridge compromise

**Threat:** An attacker replaces `sso-jwt-tpm-bridge.exe` with a malicious binary, or positions a lookalike earlier on `$PATH` so the WSL-side client spawns it instead of the real bridge.

**Mitigation:**
- The bridge path candidates are fixed install locations under `/mnt/c/Program Files/sso-jwt/` and `/mnt/c/ProgramData/sso-jwt/`; `Program Files` requires admin rights to modify on Windows.
- The bridge is distributed alongside the main installer and should be verified via package manager signatures.
- Request/response size is capped and child processes are reaped on drop (see `enclaveapp-bridge`'s `MAX_BRIDGE_RESPONSE_BYTES` + `BridgeSession::Drop`).
- `sso-jwt-tpm-bridge/src/main.rs` is a thin wrapper around `enclaveapp_tpm_bridge::BridgeServer`; protocol handling lives in `libenclaveapp` and inherits its hardening.

**Residual risk:** The WSL-side `find_bridge` falls back to `which` on `$PATH` when the fixed locations are empty, so a user-writable path entry can substitute a malicious binary. No Authenticode / `WinVerifyTrust` check is performed on the resolved bridge — documenting this as a known gap tracked under the libenclaveapp bridge PE-validation follow-up. An attacker with admin rights on the Windows host already controls the TPM regardless.

### T11: Linux software keyring weakness

**Threat:** On Linux (no SE/TPM), the keyring backend provides software-only encryption. A compromised user session can extract the token.

**Mitigation:**
- A one-time notice is printed when the keyring backend is used.
- The keyring is still encrypted by the user's login password.
- This is documented as the weakest backend.

**Residual risk:** Any process running as the user can access the keyring. This is a known limitation of desktop Linux security.

### T12: Post-handoff credential misuse (Type 4 core residual)

**Threat:** After `sso-jwt get` writes the JWT to stdout or `sso-jwt exec` injects it into a child process's environment, sso-jwt has no further control. A consumer that logs the JWT (observability agent, `set -x`, error reporter), persists it to shell history, or forwards it to a subprocess leaks the token. This is the defining Type 4 (CredentialSource) constraint.

**Mitigation:**
- `sso-jwt exec -- <cmd>` is preferred over capturing stdout, because it avoids exposing the JWT to the surrounding shell and avoids the `export` footgun (T3).
- Tokens are short-lived relative to session timeout; rotation limits blast radius.
- Documentation steers consumers toward env-var interpolation rather than logging the token.

**Residual risk:** Accepted. Once the JWT crosses the handoff boundary, the consumer is inside sso-jwt's trusted computing base. Operators MUST treat consuming tools as credential-handling code.

### T13: Cache path traversal / aliasing

**Threat:** Server name, environment name, or cache-name overrides flow into filesystem paths. An attacker-influenced value such as `../../../etc/passwd` or `foo/../bar` could traverse out of the cache directory or alias two logically-distinct caches to the same file.

**Mitigation:** `Config::encode_cache_component` (`sso-jwt-lib/src/config.rs:58-84`) applies a reversible `~XX` hex encoding so only `[A-Za-z0-9_-]` characters appear verbatim. Every other byte, including path separators and `..`, encodes to an unambiguous `~HH` sequence. The encoding is byte-by-byte (O(n)) and not regex-based, so ReDoS is not possible.

**Residual risk:** None for path escape. Two servers whose names collide after encoding would still alias, but the encoding is injective on valid UTF-8 server names.

### T14: Configuration-fetch integrity (`add-server --from-url`, `--from-github`)

**Threat:** An attacker serves a malicious server profile via a captured URL or a force-moved git tag. Installed, the profile redirects subsequent `sso-jwt` invocations to an attacker-controlled OAuth endpoint.

**Mitigation:**
- `validate_endpoint_url` (`sso-jwt-lib/src/config.rs:100-107`) rejects `http://` for all OAuth, token, and heartbeat URLs. `add-server --from-url` rejects cleartext at ingest (`sso-jwt/src/cli.rs:247`).
- `add-server --from-github` requires a pinned `owner/repo@ref/path` form (`sso-jwt/src/cli.rs:433-437`); there is no implicit `HEAD` fallback.
- A 30-second HTTP timeout and 64 KB response cap bound a malicious server's ability to stall or exhaust memory.

**Residual risk:** A git tag pinning is tamper-evident only if the operator pins a **commit SHA**, not a mutable tag — force-moved tags remain TOCTOU-exposed. Operators should prefer SHA pinning for high-trust configs.

### T15: Local configuration file tamper

**Threat:** A same-UID attacker edits `~/.config/sso-jwt/config.toml` to change `oauth_url` / `token_url` / `heartbeat_url` to attacker-controlled servers that pass the HTTPS check. On next `sso-jwt get`, the user's `client_id` and device-flow response are sent to the attacker, who can proxy to the real Okta and capture the issued JWT — or issue their own.

**Mitigation:**
- Config files are written with 0600 permissions via `atomic_write` (`sso-jwt-lib/src/config.rs:421-429`).
- HTTPS-only enforcement (T14) limits the attacker to hostnames with a valid TLS certificate.
- No file integrity check, no signed config, no warning on mtime change.

**Residual risk:** Same-UID attacker has write access, which by itself is game-over for most secrets. Documented as a general trust assumption: `~/.config/sso-jwt/` must be protected by OS-level file permissions and user-side hygiene.

### T16: Cache rollback

**Threat:** An attacker with user-level write access replaces the current `<name>.enc` cache file with an older valid ciphertext they previously exfiltrated. The old header may carry a `session_start`/`token_iat` that puts the token back inside the Fresh or RefreshWindow state, so sso-jwt serves it without re-auth.

**Mitigation:**
- Rollback is bounded by `session_timeout_secs` — once exceeded, even a "fresh"-looking cache expires and forces re-auth.
- The server ultimately enforces the JWT's own `exp`; a rolled-back token the SSO server rejects becomes a denial-of-service, not a credential grant.

**Residual risk:** Within the session-timeout window, rollback extends client-side cache hits by the difference between the old and new state. No monotonic counter or signed anti-rollback token is implemented. Operators who need stronger guarantees should run at higher risk levels (shorter windows).

### T17: Local clock manipulation

**Threat:** An attacker rolls the local clock backward. sso-jwt's classifier (`sso-jwt-lib/src/cache.rs`) sees a token it believes is Fresh and serves it even if the JWT has actually expired according to real time.

**Mitigation:**
- The server side enforces the JWT's `exp` against its own clock; a rolled-back local clock does not extend server acceptance.
- Rolling the clock forward causes sso-jwt to treat tokens as expired and re-authenticate — low harm.

**Residual risk:** Accepted. An attacker with privileges to set the system clock already has substantial control.

### T18: Malicious heartbeat endpoint issues attacker-controlled tokens

**Threat:** The heartbeat refresh (`oauth::heartbeat_refresh`, `sso-jwt-lib/src/oauth.rs:215-248`) POSTs the current token to `heartbeat_url` and caches whatever token comes back. A compromised heartbeat URL (via T15 config tamper, or a hijacked SSO backend) can issue attacker-chosen JWTs that sso-jwt will cache and hand to consumers.

**Mitigation:** `heartbeat_url` shares the HTTPS-only validation and trust anchor as `oauth_url`. Config-tamper protection (T15) is the primary defense.

**Residual risk:** The refreshed JWT is not signature-verified client-side — sso-jwt treats the SSO backend as authoritative. If the backend (or the heartbeat endpoint specifically) issues malicious tokens, sso-jwt propagates them. Out of scope for the client; the backend must protect its signing key.

### T19: Malicious `gh` on PATH during `add-server --from-github`

**Threat:** `std::process::Command::new("gh")` (`sso-jwt/src/cli.rs:361`) resolves `gh` via `$PATH`. A shim `gh` earlier on `$PATH` intercepts the fetch, reads the user's ambient GitHub credentials, and can return a crafted response.

**Mitigation:** `gh` is invoked with `stdin(Stdio::null())`, `GH_PROMPT_DISABLED=1`, argument passing (no `sh -c`), and a 30-second reader-thread timeout (`sso-jwt/src/cli.rs`). The fetched payload flows through the T14 HTTPS-only validation before a profile is installed.

**Residual risk:** PATH hijacking is a user-side compromise that defeats many defenses at once. The specific impact for sso-jwt is limited to fetching a *config profile*, which then enters the T14/T15 domain. Unlike sshenc, sso-jwt does not use `enclaveapp-core::bin_discovery` for `gh`; switching to trusted discovery is a candidate hardening.

### T20: Concurrent `sso-jwt get` race

**Threat:** Two concurrent `sso-jwt get` invocations both find the cache Dead and enter the full OAuth Device Code flow. The user sees two user-code prompts, authorizes one, and the races both write to the cache; the last `rename` wins atomically but a race window for the second prompt exists.

**Mitigation:** `atomic_write` (rename) makes the cache update atomic, so the outcome is always a valid cache, never a partial write. No flock is taken around `resolve_token`.

**Residual risk:** UX annoyance rather than a security issue. If needed, a file lock around the resolve path would serialize concurrent invocations.

### T21: Browser launch (`$BROWSER` env and `open`/`xdg-open`/`start`)

**Threat:** During the Device Code flow, sso-jwt opens the verification URI in the user's browser. If `$BROWSER` is attacker-controlled (malicious shell profile, supply-chain dotfile), an arbitrary binary runs with the user's environment.

**Mitigation:**
- `$BROWSER` is parsed via `shell_words` (not `sh -c`), so the user's configured command cannot execute injected shell metacharacters.
- The fallback `open`/`xdg-open`/`start` chain is the OS-supplied launcher.

**Residual risk:** An attacker who controls `$BROWSER` in the user's shell already has code execution at the user level. Documented as a user-side trust assumption.

### T22: Node.js NAPI boundary memory hygiene

**Threat:** `sso-jwt-napi` returns the JWT as a JavaScript `String`. Node strings are immutable; there is no way to zeroize them after use. Any downstream GC sweep leaves JWT bytes in V8 heap memory until reuse.

**Mitigation:** None at the Node layer. The Rust side continues to zeroize its own plaintext buffers on drop.

**Residual risk:** Accepted. Node consumers that require memory hygiene should switch to the CLI `exec` subcommand. Documented as a Node-specific caveat.

## Attack Surfaces

| Surface | Access Required | Impact | Mitigated By |
|---|---|---|---|
| Cache file read | User file read | Token theft | ECIES encryption (SE/TPM) |
| Cache file copy to another machine | File exfiltration | Token replay | Hardware-bound key |
| Cache file rollback | User file write | Session extension | Session timeout, server `exp` (T16) |
| Shell history / env var | Shell access | Token leak | Export detection, exec mode |
| Process memory | Root / ptrace | Token extraction | Zeroize on drop, biometric |
| Network traffic | MitM position | Token interception | TLS (rustls + webpki-roots) |
| Config file tamper | User file write | OAuth redirect | HTTPS-only validation (T15) |
| Local clock | Privilege to set clock | Serve expired token | Server-side `exp` check (T17) |
| `gh` / `$BROWSER` PATH lookup | PATH hijack | Config payload injection or arbitrary exec | HTTPS validation, shell_words parse (T19/T21) |
| SSO webservice | Network access | Token issuance | Okta MFA, device code TTL |
| TPM bridge replacement (WSL) | Admin on Windows host or PATH hijack | Key compromise | Fixed install path; PE validation is a known gap |
| Login keyring (Linux) | User session | Token extraction | Documented limitation |
| NAPI string return | Node process memory | Memory residue | None at Node layer (T22) |

## Assumptions

1. The Secure Enclave and TPM 2.0 are uncompromised and function as documented by Apple and Microsoft respectively.
2. The SSO webservice and Okta identity provider enforce MFA and are not compromised.
3. The user's operating system is not compromised at the kernel level.
4. TLS certificate authorities are not compromised.
5. The user's shell profile is not modified by an attacker (for shell integration to be effective).

## Out of Scope

- Server-side vulnerabilities in the SSO webservice or Okta.
- Physical attacks on the Secure Enclave or TPM hardware.
- Side-channel attacks (timing, power analysis) against the hardware security module.
- Supply chain attacks on the Rust toolchain or crate dependencies.
- Denial-of-service attacks against the SSO webservice.
