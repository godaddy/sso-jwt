# sso-jwt Current Defect Review

Date: 2026-04-14
Reviewer: Codex
Current status: Resolved on local checkout `8366c830fa1a75238af46bad4092bc8a2ae5575f`

## Summary

This file previously tracked findings that were valid in an older review snapshot. Those findings have now been addressed in the current tree and should not be treated as open defects.

- Resolved legacy findings from the prior report: `1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15`
- Resolved additional current defect from the re-review: `A1`
- Legacy finding `7` remained invalid as written and was superseded rather than fixed

## What Was Closed

The current tree includes fixes for the previously tracked issues in these areas:

- `add-server --from-github` no longer uses a shell-based fallback and now validates GitHub path components
- Direct-URL cache entries are namespaced by issuer-specific input instead of collapsing into one cache path
- Cached token lifetime now honors issuer expiry when present, and cached risk metadata is applied consistently on read
- Profile resolution no longer discards supported public overrides for `client_id` and `heartbeat_url`
- Security-sensitive endpoint URLs reject cleartext HTTP by default, including `add-server --from-url`
- Config loading now reports malformed or unreadable config files and rejects unknown TOML keys
- OAuth requests are form-encoded instead of hand-built
- Risk-level validation is enforced consistently across CLI, env/config, library, and N-API paths
- The TPM bridge build/protocol breakage is fixed and the workspace compiles again
- Reusable GitHub workflows are pinned to immutable SHAs
- The Node binding types/docs now expose `tokenUrl`
- Release metadata is aligned, and the winget manifests are rendered with concrete release values instead of placeholders
- Documentation now matches the shipped install layout, bridge discovery behavior, and implemented security properties

## Verification

The current tree was verified with:

```bash
cargo test --workspace
```

The current repo also includes test coverage for the corrected runtime, packaging, workflow, and documentation contracts, including:

- CLI tests for GitHub-source validation and insecure-HTTP rejection
- Cache/config/oauth tests for expiry handling, cache isolation, risk validation, config parsing, and form encoding
- N-API tests for option conversion and risk validation
- Repo metadata tests for workflow pinning, version alignment, rendered winget manifests, and documentation consistency

## Cleanup Note

This file is now a resolved-status record. If you no longer need that audit trail, it can be deleted.
