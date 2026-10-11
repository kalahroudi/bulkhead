# DR-0004: TENANT-1 is decided by the differential oracle

- Status: accepted (owner approved in session on 2026-10-11; cryptographic signature pending)
- Date: 2026-10-11
- Rules: TENANT-1

## Context
Spec 0.1.0 assigned the canary oracle to TENANT-1 (tenant identity only from host or session). While writing the Phase 1 probe, the natural deterministic check is differential: the same request with and without a client-supplied tenant header must produce identical responses. A canary check would also pass or fail depending on unrelated leaks (for example a missing tenant filter), so it cannot attribute the failure to this rule.

## Decision
Change TENANT-1's oracle from `canary` to `differential`. Nothing else about the rule changes.

## Consequences
`packages/spec/src/rules.ts` and the generated `SPEC.md` change (frozen paths, hence this record). A test in `@kalahroudi/bulkhead-verify` asserts each probe's oracle and scenario match the spec, so such drift is caught.
