# DR-0009: Phase 4 item 1 built: automated mutation checks, catalog in verify, decision lint

- Status: proposed (owner acceptance and signature pending; the builder cannot accept its own record)
- Date: 2026-10-13
- Rules: VERIFY-4 (and, through it, every rule with a probe)

## Context
DR-0007 and DR-0008 were accepted on 2026-10-13. They authorised moving the mutation catalog into
`packages/verify/` and building the decision-record lint in `packages/spec/`, both frozen, and required a
separate attacker session to review the catalog. This record lists those edits and the attacker's findings.

### Edits to frozen paths
- `packages/verify/src/mutations.ts` (catalog, moved from `scripts/`), `packages/verify/package.json` (export),
  `packages/verify/test/mutations.test.ts` and `test/decisions.test.ts` (new).
- Attacker session (separate agent, `packages/verify/` only): probe `disabled-user-denied`, fixture
  `DELETE /users/:id` and the seeded bug `disabled-user-can-login` (self-check now 18/18, no false positives).
  The existing `default-role` bug gained `disabled-user-denied` in its expected probes, the same mis-attribution
  pattern already recorded for the other session probes.
- Builder, `packages/verify/src/probes.ts`: `notes-list-canary` and `cache-canary` now require a 2xx on the
  observing read. Before, a 404 or 500 on tenant B read as "marker absent" and passed vacuously.
- `packages/spec/src/decisions.ts`, `scripts/lint-decisions.ts`, `test/decisions.test.ts`, and `lint` now also runs the
  decision lint, so `pnpm spec:lint` (part of every gate) enforces it.

## Decision
1. **The catalog lives in `packages/verify/src/mutations.ts`** and holds 27 entries. Entries may carry `also`
   edits for mutations that must defeat two independent defences. Check: `test:packages/verify/test/mutations.test.ts::each find string occurs exactly once`, `script:scripts/verify-mutations.ts`.
2. **Every probe needs a catalog entry or a recorded exemption.** The only exemption is `forged-signature`
   (BILL-2), whose route the demo does not have until Phase 5. Check: `test:packages/verify/test/mutations.test.ts::DR-0007 item 4`.
3. **A mutation no probe can catch is a named gap** that the package's unit tests must kill, judged against a
   clean baseline. Gaps are printed on every run. Check: `mutation:key-secret-not-compared`, `mutation:bootstrap-token-unchecked`, `mutation:user-list-leaks-password-hash`.
4. **The gate must be shown able to fail.** `scripts/mutation-selfcheck.ts` feeds the runner a survivor, a
   mis-attributed kill and a stale entry and requires it to reject all three; `gate:phase4` runs it before the
   catalog. A baseline that already fails is an error. Check: `script:scripts/mutation-selfcheck.ts`, `gate:phase4`.
5. **Decision records are linted and resolved.** Each numbered choice in a record that names rules cites
   `Check:` refs or says `No check:` with a reason; refs must resolve to a real probe, catalog entry, test title,
   script or gate. DR-0005 to DR-0008 were annotated; no decision text changed. Check: `test:packages/spec/test/decisions.test.ts::a choice with neither Check nor No check fails`, `test:packages/verify/test/decisions.test.ts::every ref`.
6. **Defects found by the attacker pass and fixed here:** vacuous canary reads (above); no test that listings
   hide hash material (`mutation:user-list-leaks-password-hash` survived every probe and every unit test, so a
   unit test was added); the role-change mutation was split into two so each revocation is attributed. Check: `mutation:user-list-leaks-password-hash`, `mutation:role-change-keeps-keys`, `probe:notes-list-canary`.

## Owed, not built (raised as follow-up items, not silent)
Black-box probes for lines the attacker found unprotected by any probe; each is a gap entry in the catalog, killed
only by auth unit tests today: wrong key secret with a real key id, wrong or missing bootstrap token and a second
bootstrap claim, `PATCH /users/:id/role` escalation, an admin modifying an owner, minting a key above one's role,
listings leaking hash material. Also owed: `api-key-scope` never tests the key role ceiling (its key lacks the
permission for `/private/owner`, so the 403 is vacuous for that purpose); `identity-header-differential` tries
only `x-tenant`; the two session and key `disabled` checks stay gaps because revocation shadows them over HTTP;
`unitTestsPass` can be satisfied by a syntax error in the mutated file, so a gap's attribution to a specific test
is not proven. A green gate means no known leak paths, not proof of none. Rules stay `proposed`.
No check: these are follow-up items, and each becomes a probe plus a promoted catalog entry when built.

## Consequences
`pnpm gate:phase4` is `gate:phase3`, then the gate self-check, then the full catalog (about five to eight
minutes). CRYPTO-* work has not started and needs its own scoping record before any code.
