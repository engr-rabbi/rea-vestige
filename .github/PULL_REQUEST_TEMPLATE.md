<!-- Pull requests: keep them small and verifiable. -->

## What

<!-- One logical change. Link the issue. -->

## Why

<!-- The analysis question this improves. Reference the improvement matrix in docs/ASSESSMENT-REA.md if applicable. -->

## Verification (commands + actual results)

- [ ] `npm run typecheck`
- [ ] `npm run lint`
- [ ] `npm test` (state pass/fail counts)
- [ ] `npm run bench:record` (parser/analysis changes only) — attach BENCHMARKS.md diff
- [ ] Security-relevant changes: `docs/THREAT-MODEL.md` updated + tests in `tests/security/`

## Honesty checklist

- [ ] No capability is advertised beyond what tests demonstrate
- [ ] New findings/evidence kinds link to evidence and declare limitations
- [ ] Dependency direction respected (see docs/ARCHITECTURE.md §2)
