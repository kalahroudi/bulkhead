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

Phase 0 is accepted (DR-0003). Phase 1 is accepted. Phase 2 is accepted (DR-0005). Phase 3 (auth) is accepted (DR-0006). Phase 4 has started: DR-0007 and DR-0008 are accepted; DR-0009 (accepted) records the automated mutation checks built under them (catalog in `packages/verify/src/mutations.ts`, runner in `scripts/`, decision lint in `packages/spec/`). DR-0010 (crypto scoping) is accepted; its steps (a) to (g) are built (DR-0014, proposed): classification enforcement, sealed handle, key hierarchy, nonce counter, shredding, write-only secrets, and the BOOT-1 launcher check. The CRYPTO rules stay `proposed` until Phase 7. The Better Auth spike (DR-0011) is done and reported in DR-0015 (proposed): it fits behind the hook, nothing is adopted, and the owner decides; `packages/auth-betterauth` and `examples/demo-betterauth` are unwired from the default demo. The Better Auth spike (PR #17) is merged. Next in the agreed order: making the verifier usable against an app other than the demo; DR-0016 (proposed) scopes it and is built: the contract is written down in `docs/verify-target-contract.md`, a missing route is UNVERIFIED, cookie name, host suffix and webhook secret are target settings (`verify-target.json`), and `examples/contract-app` (own tables and layout, host suffix `contract.localhost`) passes the same 12 rules in `gate:phase4` with no probe edits.

## Commands

- `pnpm gate:phase0`: typecheck, tests, spec lint, and check that `SPEC.md` matches the catalog.
- `pnpm gate:phase1`: phase 0 gate plus the verify self-check (all seeded bugs caught, no false positives).
- `pnpm gate:phase2`: phase 1 gate, route manifest check, and a black-box verify of the tenancy rules (TENANT-1/4/5) against the demo Worker running in local workerd.
- `pnpm gate:phase3`: phase 2 gate plus a black-box verify of the auth rules (AUTH-1..4, alongside TENANT-1/4/5) against the demo Worker.
- `pnpm gate:phase4`: phase 3 gate, then `scripts/mutation-selfcheck.ts` (proves the runner fails on survivors, mis-attribution and stale entries), then `scripts/verify-boot.ts` (BOOT-1: the demo refuses to boot with each key missing or malformed), then the same probes against `examples/demo-betterauth` (the DR-0011 spike), then `scripts/verify-mutations.ts` (mutates a scratch copy; exactly the named probes must fail; a baseline that already fails is an error).
- `pnpm spec:lint` (part of every gate) also lints decision records: each numbered choice must cite `Check:` refs or say `No check:` and why; `packages/verify/test/decisions.test.ts` resolves every ref.
- `node packages/plane/src/cli.ts [--once] [--log-dir .bulkhead]`: terminal view of the event log.
- `pnpm --filter @kalahroudi/bulkhead-spec catalog`: regenerate `SPEC.md`.

## Naming

npm scope is `@kalahroudi`. Packages are `@kalahroudi/bulkhead-<name>`; the CLI is `@kalahroudi/bulkhead`.
