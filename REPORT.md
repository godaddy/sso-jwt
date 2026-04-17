# sso-jwt — Open Findings

Snapshot of findings still live in the current tree after the 2026-04 audit sweep.
All earlier defect and design-concern items (D1-D5, C1-C4, L1, L3) were fixed,
moved upstream into the shared `enclaveapp-tpm-bridge` crate, or otherwise
resolved. This file now tracks only work that is still outstanding.

## Low

### L2. README lacks Node.js usage example

`README.md` references Node.js support and links to the NAPI crate directory, but
there is no inline `getJwt()` example. The `JwtOptions` interface and function
signature are shown in `DESIGN.md:381-404`, so the information exists in-repo —
it's just not easy to find from the README.

**Remediation:** Add a short Node.js usage block to `README.md` (install,
minimal `getJwt()` call, link to `DESIGN.md` for the full options table).

---

*All prior D/C/L findings not listed above were either fixed in code or moved
out of scope when the TPM bridge was replaced with a thin wrapper around
`enclaveapp_tpm_bridge::BridgeServer`; removed from this report on 2026-04-16.*
