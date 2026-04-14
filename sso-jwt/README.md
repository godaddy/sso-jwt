# sso-jwt (CLI)

Thin CLI wrapper around [`sso-jwt-lib`](../sso-jwt-lib/) for obtaining JWTs and injecting them into child processes safely.

## Current commands

- `shell-init`
- `exec`
- `install`
- `uninstall`
- `add-server`

Running `sso-jwt` with no subcommand resolves a token and prints it to stdout.

## Common usage

```bash
# preferred
sso-jwt exec -- terraform apply

# stdout for a single child process
SSO_JWT=$(sso-jwt) terraform apply

# clear cache and exit
sso-jwt --clear

# use a specific server profile
sso-jwt --server myco --environment dev

# install shell guardrails
eval "$(sso-jwt shell-init zsh)"
```

`exec` uses `SSO_JWT` by default. Override it with:

```bash
sso-jwt exec --env-var COMPANY_JWT -- terraform apply
```

## Install behavior

- on Windows: configures bundled WSL integration
- on other platforms: prints the shell-init line to add manually

## Architecture

The CLI owns:

- argument parsing and dispatch
- shell-init generation
- child-process exec behavior
- server-profile import via `add-server`

Token resolution, cache handling, and OAuth behavior live in [`sso-jwt-lib`](../sso-jwt-lib/).

## License

MIT
