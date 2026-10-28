# Contributing to Vestige

Thanks for helping make evidence-driven reverse engineering better. This project values
**correctness over feature count**: a capability that cannot be tested honestly does not ship.

## Development setup

```bash
git clone <your-fork>
cd vestige
npm install          # exact-pinned deps, lockfile committed
npm run build        # tsc -p tsconfig.build.json
npm test             # full suite
npm run typecheck && npm run lint
```

Node.js ≥ 20.19 required (24.x recommended).

## Quality gates (all required before merge)

| Gate | Command |
|---|---|
| Types | `npm run typecheck` (strict) |
| Lint | `npm run lint` |
| Tests | `npm test` — unit, integration, security, regression, e2e |
| Benchmarks (parser changes) | `npm run bench:record` and review `docs/BENCHMARKS.md` diff |

## Ground rules

1. **Evidence discipline** — new findings must link to evidence; new evidence kinds must be
   declared in `src/domain/evidence.ts`; never fabricate observations.
2. **No advertised-but-untested capability** — if a format/operation isn't covered by a
   fixture with ground truth, it doesn't get advertised in `capabilities()`.
3. **Dependency direction** — see `docs/ARCHITECTURE.md` §2. Providers never import services;
   domain imports nothing but util.
4. **Security-sensitive changes** must update `docs/THREAT-MODEL.md` and include tests in
   `tests/security/`.
5. **Small PRs** — one logical change; include the command outputs of the gates you ran.

## Adding a provider

See `docs/PROVIDERS.md` § "Adding a provider". Requirements: fixture builders with embedded
ground truth, unit tests asserting precision/recall on those fixtures, a golden regression
test, advertised limitations, and availability diagnostics.

## Commit style

Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`). Releases are cut from
conventional-commit history.

## License

By contributing you agree your contributions are licensed under the repository's MIT license.
