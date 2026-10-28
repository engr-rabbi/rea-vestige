# Third-party notices

Vestige runtime dependencies (exact-pinned in `package.json` / `package-lock.json`).
Transitive dependency licenses are catalogued by `npm ls --all` and `npm audit`; the entries
below cover the packages Vestige imports directly.

| Package | Version | License | Use |
|---|---|---|---|
| [`@modelcontextprotocol/server`](https://github.com/modelcontextprotocol/modelcontextprotocol) | 2.4.0 | MIT | MCP server SDK (tools/resources/prompts, transports) |
| [`@modelcontextprotocol/client`](https://github.com/modelcontextprotocol/modelcontextprotocol) | 2.4.0 | MIT | MCP client used by the test suite (dev) |
| [`zod`](https://zod.dev) | 4.6.7 | MIT | Schema validation and tool contracts |
| [`acorn`](https://github.com/acornjs/acorn) | 8.19.0 | MIT | JavaScript parser (javascript provider) |
| [`acorn-walk`](https://github.com/acornjs/acorn) | 8.3.4 | MIT | AST traversal (javascript provider) |

Dev toolchain (not shipped): TypeScript (Apache-2.0), Vitest (MIT), ESLint + typescript-eslint
(MIT), @types/node (MIT), @eslint/js (MIT).

## External tools (optional, not distributed with Vestige)

- **Ghidra** — National Security Agency. Licensed under Apache-2.0. Optional decompilation
  backend; downloaded and installed separately by the operator from
  <https://ghidra-sre.org/>. Vestige communicates via Ghidra's public headless scripting API
  and bundles its own bridge script (`vestige_dump.py`) under this repository's MIT license.

## Attribution

- The repository assessment of `morluto/rea` (MIT, © 2026 morluto) informed this project's
  design priorities; see `docs/ASSESSMENT-REA.md`. Vestige is an independent implementation
  and claims no affiliation with the REA project.
