# sso-jwt-tpm-bridge

Windows-only TPM 2.0 bridge process for WSL environments.

When `sso-jwt` runs under WSL, it detects that the TPM hardware is owned by the Windows host and spawns this bridge process to perform TPM operations. Communication happens via JSON-RPC over stdin/stdout pipes.

## How It Works

```
  WSL (Linux)                          Windows Host
+------------------+    stdin/stdout   +------------------------+
| sso-jwt          | <--------------> | sso-jwt-tpm-bridge.exe |
| (Linux binary)   |   JSON-RPC over  | (Windows binary)       |
|                  |   pipes via       |                        |
|                  |   WSL interop     | Uses CNG + TPM 2.0    |
+------------------+                   +------------------------+
```

## Installation

The bridge is installed alongside `sso-jwt.exe` on the Windows host:

```
C:\Program Files\sso-jwt\sso-jwt-tpm-bridge.exe
```

The WSL `sso-jwt` binary looks for it at this path automatically.

## Protocol

Request (one JSON object per line on stdin):
```json
{"method": "init", "params": {"data": null, "biometric": false}}
{"method": "encrypt", "params": {"data": "<base64>", "biometric": false}}
{"method": "decrypt", "params": {"data": "<base64>", "biometric": false}}
{"method": "destroy", "params": {"data": null, "biometric": false}}
```

Response (one JSON object per line on stdout):
```json
{"result": "<base64>", "error": null}
{"result": null, "error": "description of failure"}
```

## Building

This crate must be cross-compiled for Windows:

```bash
# From macOS/Linux with the Windows target installed
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc -p sso-jwt-tpm-bridge

# Or build natively on Windows
cargo build --release -p sso-jwt-tpm-bridge
```

On non-Windows platforms, the binary compiles but prints an error and exits if run directly.

## License

MIT
