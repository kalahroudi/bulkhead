# DR-0008: Interim mutation runner outside frozen paths

- Status: accepted (owner approved in session on 2026-10-13; cryptographic signature pending). Superseded by DR-0009 for the catalog location; the runner design stands.
- Date: 2026-10-13
- Rules: VERIFY-4

## Context
DR-0007 proposes automated mutation checks, with the catalog and DR lint in `packages/verify/` and
`packages/spec/` (frozen). DR-0007 is not yet accepted, so those edits are not allowed. Waiting would leave
VERIFY-4 manual for another session, so the part that needs no frozen path was built now.

## Decision
1. `scripts/mutations.ts` (catalog) and `scripts/verify-mutations.ts` (runner) implement DR-0007 items 1-3
   with no change to any frozen path. `pnpm gate:phase4` is `gate:phase3` plus the runner. Check: `script:scripts/verify-mutations.ts`, `gate:phase4`.
2. The runner copies the workspace to a scratch directory, checks the unmutated copy passes every probe, then
   applies each mutation there (role change is split into two entries so each revocation is attributed to its own probe), runs `scripts/verify-kernel.ts` against it, and restores the file. The working
   tree is never edited. Each `find` must match exactly once. The failing probe set must equal `expect`
   exactly: a missing probe is a worthless scenario, an extra one a mis-attributed scenario. Check: `script:scripts/mutation-selfcheck.ts`.
3. A mutation no probe can catch yet is recorded as a named `gap` and must be killed by the package's unit
   tests, otherwise the gate fails. It is reported on every run, never skipped. Check: `mutation:tenant-binding-check-removed`, `mutation:login-ignores-disabled`.
4. When DR-0007 is accepted, the catalog moves to `packages/verify/` unchanged, and the DR lint (item 5) is
   built there. This record is then superseded. Moving needs an attacker session to review the catalog. Check: `test:packages/verify/test/mutations.test.ts::each find string occurs exactly once` (the catalog now lives in `packages/verify/`; this record is superseded by DR-0009).

## Findings from the first run (12 mutations, all as recorded)
- Role change without revocation also fails `key-revocation`, correctly: demoting a minter revokes its keys.
- **Gap:** the three `disabled` checks (session query, key lookup, login) survive every black-box probe and
  are killed only by auth unit tests. Only `login-ignores-disabled` can be closed by an HTTP probe (disable a
  user, then log in). The session and key checks are defence in depth behind revocation (`DELETE /users/:id`
  already deletes the user's sessions and revokes their keys), so over HTTP they are near-equivalent mutants.
  The runner requires the auth unit tests to pass unmutated and fail when mutated, so these stay protected.

## Consequences
- The gate adds roughly five minutes (one workerd boot of about 20 seconds per mutation, plus unit runs).
- Catalog entries are exact-text replacements, so a refactor that moves a line makes its entry error until
  updated. That is deliberate: a stale entry must be seen, not skipped.
- A killed mutation shows a probe can fail. It does not prove correctness. A green report still means no
  known leak paths.
- Not done, deferred with DR-0007: enforcing that a new probe ships with a catalog entry (item 4) and the
  decision-record lint (item 5). Neither can be built outside `packages/spec/` and `packages/verify/`.
