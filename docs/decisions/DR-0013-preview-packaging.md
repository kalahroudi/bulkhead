# DR-0013: Package four crates as a public 0.1.0-preview; frozen-path packaging edits

- Status: proposed (owner approved the preview release and the package set in session on 2026-10-13; acceptance and signature pending for this record)
- Date: 2026-10-13
- Rules: ROUTE-1, ROUTE-2, TENANT-1, AUTH-1, AUTH-2, AUTH-3, AUTH-4

## Context
"Release" means a public npm package others can use. The packages ran only from TypeScript source through Node's type stripping, which Node refuses inside `node_modules`, so they could not be installed and used. The owner chose a clearly labelled preview of `core`, `auth`, `spec` and `verify`; `plane` and the demo app stay private.

### Edits to frozen paths (mechanical, no behaviour change)
- `packages/core/package.json`, `packages/spec/package.json`, `packages/verify/package.json`: version `0.1.0-preview.0`, metadata, `files`, `engines`, `publishConfig`.
- `packages/core/src/tenant/object.ts`: `private store` became the ECMAScript private field `#store`. TypeScript cannot emit a `private` member of an exported anonymous class into a declaration file; runtime behaviour is identical and the core tests pass unchanged.
- `packages/{core,auth,spec,verify}/package.json` also gain `prepack: pnpm build` so a tarball cannot be packed without `dist`.
- `packages/verify/src/run.ts`: the fixture launcher picks `server.ts` when running from source and `server.js` when running from the compiled package.
- `packages/{core,auth,spec,verify}/LICENSE` and `README.md` added.

## Decision
1. **Dev exports keep pointing at source; `publishConfig.exports` and `bin` point at `dist/`.** pnpm applies the override when packing, so the monorepo, the gates and the demo app run exactly as before and only the tarball changes. Check: `script:scripts/consumer-test.ts`, `gate:release`.
2. **A tarball contains only `dist`, `README.md`, `LICENSE` and `package.json`,** with no TypeScript source, no tests, no fixture source, and no `workspace:` references. Check: `script:scripts/consumer-test.ts`.
3. **The README quickstart is the tested quickstart.** The consumer test extracts the `jsonc` and `ts` blocks from `README.md`, installs the packed tarballs into a clean project outside the repo, typechecks the code against the published declarations, boots it in workerd and drives the real flow (401 unauthenticated, bootstrap 403 and 201, login, protected route 200, cross-tenant cookie 401, unknown host 404), then runs the installed verifier's self-check. A broken quickstart turns it red (shown by corrupting the import). Check: `script:scripts/consumer-test.ts`.
4. **`verify run` only works against apps exposing the probe-contract routes** (`/whoami`, `/notes`, `/summary`, `/private/*`), which only the demo app has. The README says so and does not claim otherwise. A packaged probe-route helper is owed. No check: the limit is documented, and a helper is future work, so nothing can enforce it yet.
5. **Publishing is the owner's manual script, not a workflow.** `scripts/release.ts <version>` (DR-0014) exports a clean public copy, checks it, pushes it to the public repo and publishes to npm; the private repo has no release workflow and holds no publish credentials. `ci.yml` runs `gate:release` on pull requests and has not run on GitHub from this environment. No check: only a real run on GitHub shows the workflow works.

## Consequences
`pnpm gate:release` is `gate:phase4` plus the consumer test (about one minute more). Not yet done: a monitored security email in `SECURITY.md` (owner), npm scope 2FA and provenance setup (owner), the first publish (owner), the probe-route helper, and the Better Auth and crypto work. All rules stay `proposed`. A green report means no known leak paths, not proof of none.
