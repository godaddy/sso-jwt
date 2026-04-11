# sso-jwt (CLI)

Command-line tool for obtaining SSO JWTs with hardware-backed secure caching. This is the binary crate -- it's a thin CLI wrapper around [`sso-jwt-lib`](../sso-jwt-lib/).

## Installation

```bash
cargo install --path .
```

## Usage

```bash
# Get a JWT for a single command (recommended)
COMPANY_JWT=$(sso-jwt) terraform apply

# Exec mode -- JWT never touches stdout
sso-jwt exec -- terraform apply

# Shell integration for export detection
eval "$(sso-jwt shell-init)"

# Clear cached token
sso-jwt --clear

# Dev environment, high security
sso-jwt -e dev --risk-level 3 --biometric
```

Run `sso-jwt --help` for all options.

## Shell Integration

Add to your shell profile:

```bash
# zsh
eval "$(sso-jwt shell-init zsh)"

# bash
eval "$(sso-jwt shell-init bash)"

# fish
sso-jwt shell-init fish | source
```

This installs a wrapper function that detects `export COMPANY_JWT=$(sso-jwt)` and refuses to emit the token, guiding users toward the safer `COMPANY_JWT=$(sso-jwt) command` or `sso-jwt exec` patterns.

## Architecture

The CLI contains only:
- **cli.rs** -- Clap argument parsing and dispatch
- **exec.rs** -- Fork/exec with JWT injected into child environment
- **shell_init.rs** -- Shell integration script generation (bash/zsh/fish)

All core logic (caching, OAuth, secure storage, JWT parsing) lives in [`sso-jwt-lib`](../sso-jwt-lib/).

## License

MIT
