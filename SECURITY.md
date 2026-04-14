# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in sso-jwt, report it privately.

**Do not open a public GitHub issue for security vulnerabilities.**

Email: Report via GitHub's private vulnerability reporting feature on the
[sso-jwt repository](https://github.com/godaddy/sso-jwt/security/advisories/new),
or contact the maintainer directly.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

You will receive an acknowledgment within 72 hours. A fix will be developed
and released as quickly as possible, with credit given to the reporter
(unless anonymity is requested).

## Supported Versions

| Version | Supported |
|---|---|
| 0.5.x | Yes |

Only the latest release receives security fixes.

## Security Model Summary

sso-jwt encrypts cached JWTs at rest using hardware-backed keys:

- **Tokens are encrypted with ECIES** using a P-256 key pair generated in
  the Secure Enclave (macOS), TPM 2.0 (Windows/Linux), or a software
  fallback. The private key never leaves the hardware.
- **No plaintext tokens on disk.** Cached tokens are stored as ECIES
  ciphertext. Plaintext exists only briefly in process memory.
- **Shell integration detects accidental `export` usage.** The `shell-init`
  hook warns when tokens are exported into persistent environment variables.
- **`exec` mode isolates tokens.** The JWT is injected directly into the
  child process environment without ever touching stdout.
- **In-memory token buffers are zeroized on drop.**
- **Absolute session timeouts** prevent indefinite token refresh chains.

### What sso-jwt does NOT protect against

- Root/admin compromise (root can call SE/TPM APIs or dump process memory)
- Kernel exploits
- Physical attacks on the Secure Enclave or TPM hardware
- OAuth Device Code phishing (social engineering to approve a fake code)
- Software fallback key theft on Linux without TPM

See [THREAT_MODEL.md](THREAT_MODEL.md) for a detailed analysis.

## Dependencies

sso-jwt uses a conservative set of dependencies. Key external crates:

- `enclaveapp-*`: Shared hardware-backed key management (libenclaveapp)
- `reqwest` + `rustls`: HTTPS client for OAuth and heartbeat endpoints
- `clap`: CLI argument parsing
- `serde`, `toml`: Configuration serialization
- `zeroize`: Secure memory wiping

All dependencies are published on crates.io and are widely used in the
Rust ecosystem.
