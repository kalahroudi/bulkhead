# AGENTS.md (same file as CLAUDE.md)

Bulkhead turns a Cloudflare Workers project into a multi-tenant service, with security enforced by structure and proven by an independent verifier. Read `SPEC.md` (generated from `packages/spec/src/rules.ts`) before changing anything.

## Ground rules

- Discipline for every change: a new probe ships with a mutation catalog entry (or a recorded exemption); a decision record's numbered choices cite their check or say why none exists; a green gate is only trusted if the gate itself has been shown able to fail; non-trivial work gets a review by a separate agent before merge.

- The spec is the source of truth. If the spec and the code disagree, the code is wrong.
- Nothing is done until `verify` passes. Never claim a feature works from reading code.
- Never bypass hooks, never use `--no-verify`, never edit `verify` or other read-only paths.
- A route without a policy is a bug. A query without the scoped handle is a bug. Plaintext in a classified field is a bug.
- Ambiguity is a question for the human, recorded as a decision record in `docs/decisions/`, not a guess.
- Conflicts resolve in a fixed order: security, then performance, then flexibility.
- Honest limits: a green report means no known leak paths, not proof of none.

## Roles

- Builder: implements one phase against the spec. Cannot edit `SPEC.md`, `packages/spec/`, `packages/verify/` or `packages/core/` (see `FROZEN_PATHS`).
- Attacker: a separate session that extends verify scenarios for the phase. Cannot edit core.
- The human holds the signing key. The agent never does.

## Current state

Phase 0 is accepted (DR-0003). Phase 1 is accepted. Phase 2 is accepted (DR-0005). Phase 3 (auth) is accepted (DR-0006). Phase 4 has started: DR-0007 and DR-0008 are accepted; DR-0009 (accepted) records the automated mutation checks built under them (catalog in `packages/verify/src/mutations.ts`, runner in `scripts/`, decision lint in `packages/spec/`). Crypto (CRYPTO-*) is scoped in DR-0010 (proposed) and not started. DR-0011 (proposed) scopes a time-boxed Better Auth evaluation. The packages are prepared as a public `0.1.0-preview` (DR-0013, proposed): not security-attested, no encryption at rest, no billing or provisioning.

## Commands

- `pnpm gate:phase0`: typecheck, tests, spec lint, and check that `SPEC.md` matches the catalog.
- `pnpm gate:phase1`: phase 0 gate plus the verify self-check (all seeded bugs caught, no false positives).
- `pnpm gate:phase2`: phase 1 gate, route manifest check, and a black-box verify of the tenancy rules (TENANT-1/4/5) against the demo Worker running in local workerd.
- `pnpm gate:phase3`: phase 2 gate plus a black-box verify of the auth rules (AUTH-1..4, alongside TENANT-1/4/5) against the demo Worker.
- `pnpm gate:phase4`: phase 3 gate, then `scripts/mutation-selfcheck.ts` (proves the runner fails on survivors, mis-attribution and stale entries), then `scripts/verify-mutations.ts` (mutates a scratch copy; exactly the named probes must fail; a baseline that already fails is an error).
- `pnpm gate:release`: phase 4 gate, then `scripts/consumer-test.ts`: packs `core`, `auth`, `spec`, `verify`, checks the tarballs, installs them into a clean project, typechecks and boots the README quickstart in workerd, and runs the installed verifier's self-check. Publishing is the owner's action: `node scripts/release.ts <version>` (`--dry-run` first); see DR-0014.
- `node scripts/release.ts <version> [--dry-run]`: exports a clean public copy of the repo (allowlist, exact text fixes, product-guarantee rules only), scans it and the tarballs for private material, runs the public gate on the exact tarballs, pushes to the public repo (creating `main` if missing, one atomic push of branch and tag), then publishes to npm. `scripts/release-selftest.ts` (part of `gate:release`) proves the scan, the export and the git flow can fail.
- `pnpm spec:lint` (part of every gate) also lints decision records: each numbered choice must cite `Check:` refs or say `No check:` and why; `packages/verify/test/decisions.test.ts` resolves every ref.
- `node packages/plane/src/cli.ts [--once] [--log-dir .bulkhead]`: terminal view of the event log.
- `pnpm --filter @kalahroudi/bulkhead-spec catalog`: regenerate `SPEC.md`.

## Naming

npm scope is `@kalahroudi`. Packages are `@kalahroudi/bulkhead-<name>`; the CLI is `@kalahroudi/bulkhead`.
