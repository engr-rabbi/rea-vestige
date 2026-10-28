# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Reporting a vulnerability

**Do not open a public issue for security reports.** Use GitHub's private security advisory
("Report a vulnerability" on the repository's Security tab). Include: affected version
(`vestige version`), reproduction steps, and impact assessment. Expect an initial response
within 7 days; we will credit reporters in the changelog unless anonymity is requested.

## Responsible use

Vestige is a tool for **authorized** software analysis: your own applications, samples you are
contractually/legally permitted to inspect, or defensive security work. You are responsible for
complying with all applicable laws and licenses. Vestige deliberately contains no features for
license bypass, credential theft, stealth, unauthorized persistence, or covert operation.

## Security design summary

- Explicit target registration; nothing is analyzed unless registered (`VESTIGE_ALLOWED_ROOTS` can further restrict registration).
- Read-only analysis of originals; isolated workspace for derived files.
- Canonical path validation: `realpath`, symlink policy, traversal + NUL rejection.
- Shell-free process execution (argv arrays only), output caps, timeouts, SIGTERM→SIGKILL ladder, AbortSignal cancellation.
- Targets are never executed to inspect them; no runtime observation exists in v0.1.
- Content-addressed, tamper-checked evidence (re-verified on every read).
- Bearer-token HTTP auth (constant-time compare) for non-loopback binds; Host/Origin allowlists; 8 MiB body cap.
- Central log redaction; stdout reserved for protocol bytes in stdio mode.
- Exact-pinned runtime dependencies (4 packages); `npm audit` gate in CI.

Full analysis: [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).
