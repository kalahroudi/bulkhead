# AGENTS.md (same file as CLAUDE.md)

Bulkhead turns a Cloudflare Workers project into a multi-tenant service, with security enforced by structure and proven by an independent verifier. Read `SPEC.md` (generated from `packages/spec/src/rules.ts`) before changing anything.

## Ground rules

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

Phase 0 is accepted (DR-0003). Phase 1 is accepted. Phase 2 is accepted (DR-0005). Phase 3 (auth) is built and passes `gate:phase3`; DR-0006 awaits owner acceptance.

## Commands

- `pnpm gate:phase0`: typecheck, tests, spec lint, and check that `SPEC.md` matches the catalog.
- `pnpm gate:phase1`: phase 0 gate plus the verify self-check (all seeded bugs caught, no false positives).
- `pnpm gate:phase2`: phase 1 gate, route manifest check, and black-box verify against the demo Worker running in local workerd.
- `pnpm gate:phase3`: phase 2 gate plus the auth package tests and black-box AUTH-1..4 probes against the demo Worker.
- `node packages/plane/src/cli.ts [--once] [--log-dir .bulkhead]`: terminal view of the event log.
- `pnpm --filter @kalahroudi/bulkhead-spec catalog`: regenerate `SPEC.md`.

## Naming

npm scope is `@kalahroudi`. Packages are `@kalahroudi/bulkhead-<name>`; the CLI is `@kalahroudi/bulkhead`.
