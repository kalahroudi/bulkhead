# DR-0001: npm scope and package naming

- Status: accepted (owner approved in session on 2026-10-11; cryptographic signature pending, signing arrives with the Phase 7 CLI)
- Date: 2026-10-11
- Rules: none

## Context
The plan proposed `@bulkhead/*`, but availability of that scope was unchecked and "bulkhead" is a common resilience-pattern term.

## Decision
Publish under the owner's scope `@kalahroudi`. Packages are `@kalahroudi/bulkhead-spec`, `-core`, `-verify`, `-plane`, `-stripe`, `create-bulkhead` equivalent TBD; the CLI is `@kalahroudi/bulkhead`.

## Consequences
No dependency on claiming the `@bulkhead` scope. The npm org/scope `@kalahroudi` must still be confirmed owned before first publish. The `create-` scaffold name must be decided before Phase 8.

## Naming exceptions
Rule IDs in `SPEC.md` (area prefixes TENANT, ROUTE, AUTH, CRYPTO, BOOT, BILL, DOMAIN, HTTP, LIFE, VERIFY, GATE, SPEC, PLANE) are the canonical ones. The IDs in the Plane mockup (DATA-2, SEC-5, ISO-4) are sample data only.
