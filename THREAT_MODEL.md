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

**Threat:** Proactive heartbeat refresh keeps a session alive indefinitely, creating unbounded credential exposure.

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

**Threat:** An attacker replaces `sso-jwt-tpm-bridge.exe` with a malicious binary.

**Mitigation:**
- The bridge path is fixed at installation time (`/mnt/c/Program Files/sso-jwt/sso-jwt-tpm-bridge.exe`).
- `Program Files` requires admin rights to modify on Windows.
- The bridge is distributed alongside the main installer and should be verified via package manager signatures.

**Residual risk:** An attacker with admin rights on the Windows host could replace the bridge binary. But an attacker with admin rights already controls the TPM.

### T11: Linux software keyring weakness

**Threat:** On Linux (no SE/TPM), the keyring backend provides software-only encryption. A compromised user session can extract the token.

**Mitigation:**
- A one-time notice is printed when the keyring backend is used.
- The keyring is still encrypted by the user's login password.
- This is documented as the weakest backend.

**Residual risk:** Any process running as the user can access the keyring. This is a known limitation of desktop Linux security.

## Attack Surfaces

| Surface | Access Required | Impact | Mitigated By |
|---|---|---|---|
| Cache file read | User file read | Token theft | ECIES encryption (SE/TPM) |
| Cache file copy to another machine | File exfiltration | Token replay | Hardware-bound key |
| Shell history / env var | Shell access | Token leak | Export detection, exec mode |
| Process memory | Root / ptrace | Token extraction | Zeroize on drop, biometric |
| Network traffic | MitM position | Token interception | TLS (rustls + webpki-roots) |
| SSO webservice | Network access | Token issuance | Okta MFA, device code TTL |
| TPM bridge replacement (WSL) | Admin on Windows host | Key compromise | Fixed path in Program Files |
| Login keyring (Linux) | User session | Token extraction | Documented limitation |

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
