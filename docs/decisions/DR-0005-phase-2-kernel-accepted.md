# DR-0005: Phase 2 kernel accepted

- Status: accepted (owner approved in session on 2026-10-11; cryptographic signature pending)
- Date: 2026-10-11
- Rules: TENANT-1..5, ROUTE-1..4, AUTH-1, BOOT-1

## Context
Phase 2 adds the tenant and API kernel (`@kalahroudi/bulkhead-core`) and a demo Worker
(`examples/demo-app`). `pnpm gate:phase2` passes: typecheck, tests, spec lint, catalog check, the
verify self-check, the route-manifest check, and a black-box verify run against the demo Worker in
local workerd. TENANT-1, TENANT-4 and TENANT-5 pass with 0 findings.

Building the phase also required editing `packages/verify`, a frozen path: a metamorphic oracle and
the `add-tenant-metamorphic` probe for TENANT-4, a second probe mapped to the `missing-tenant-filter`
seeded bug, and a `--rules` filter so the gate can exercise the applicable scenarios. The repository's
process assigns verify to a separate attacker session. These edits were made by the builder session
instead, so this record documents them explicitly rather than treating them as routine.

## Decision
Accept Phase 2. Record the verify edits above and the following known limitations, so each is a
decision rather than a silent gap:

1. ROUTE-1 (invariant) is proven by unit tests and the committed route-manifest check, not a
   black-box scenario: verify reaches the app over HTTP only and cannot observe a startup failure. Check: `test:packages/core/test/kernel.test.ts::ROUTE-1`, `gate:phase2` (route manifest check).
2. The cache-canary probe (TENANT-5) passes trivially against the demo, whose `/summary` route has no
   cache; it still catches the fixture's shared-cache bug. TENANT-5's log and export dimensions are
   also unproven, as no logs or exports exist yet. Check: `probe:cache-canary`, `mutation:summary-cached-across-tenants` (a shared cache in the demo is caught). No check: log and export leaks cannot be probed until logs and exports exist.
3. BILL-2 is skipped against the demo because the demo has no billing routes. The `--rules` filter
   refuses unknown rule ids and refuses to select nothing, so a typo cannot yield a green run. Check: `test:packages/verify/test/verify.test.ts::the rule filter refuses unknown ids`. No check: BILL-2 itself cannot be probed until billing routes exist (Phase 5); see the exemption for `forged-signature` in the mutation catalog.
4. Mutation checks that break the real kernel (VERIFY-4) are not automated. Phase 2 verified them by
   hand (one shared database produced three findings; trusting `x-tenant` failed TENANT-1). Automated
   mutation checks remain Phase 9 / nightly work per the build plan. Check: `script:scripts/verify-mutations.ts`, `script:scripts/mutation-selfcheck.ts`, `gate:phase4` (automated by DR-0007).
5. Rules stay `proposed`; no attestation exists until Phase 7. Check: `test:packages/spec/test/spec.test.ts::every shipped rule starts as proposed`.

## Consequences
Phase 3 (auth) may begin from this tree once the owner signs. The attacker session still owes an
independent pass over the TENANT-4 probe and the `bugs.ts` mapping; this record does not substitute
for it. Future changes to `packages/verify` continue to need a decision record.
