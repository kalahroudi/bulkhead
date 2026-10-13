# DR-0006: Phase 3 auth: core hook change, verify additions, known limits

- Status: accepted (owner approved in session on 2026-10-12; cryptographic signature pending)
- Date: 2026-10-11
- Rules: AUTH-1, AUTH-2, AUTH-3, AUTH-4, ROUTE-2 (manifest gains `permission`)

## Context
Phase 3 adds per-tenant users, sessions and API keys. Auth lives in a new, unfrozen package
(`@kalahroudi/bulkhead-auth`) that plugs into core's existing `authenticate` hook. Two frozen paths
still had to change, as in DR-0005, so each edit is recorded here.

### Edits to `packages/core/` (frozen)
1. `authenticate(req, tenant, db)` now receives the tenant-scoped handle. Sessions and keys must live
   in the tenant's own Durable Object (TENANT-3); keeping them in the control plane would break that
   rule, and stateless cookies cannot be revoked (AUTH-2). The gate still runs before any handler;
   handlers receive the same handle only after it passes (ROUTE-4). Alternatives rejected: no core
   edit (stateless sessions fail AUTH-2), or an owner-applied patch (same change, slower).
2. `User.permissions?` and `Policy.permission?`. A credential that carries permissions (API keys,
   AUTH-4) reaches only routes that declare a permission it holds; a route that declares none is
   unreachable by keys (fail closed). Sessions carry no permission set, so role alone decides.
   `permission` appears in the route manifest (ROUTE-2), so widening it is visible to CODEOWNERS.

### Edits to `packages/verify/` (frozen)
Seven probes for AUTH-1..4 (`no-default-role`, `session-rotation`, `cookie-flags`, `logout-revokes`,
`role-change-revokes`, `role-matrix`, `api-key-scope`), a role-differential oracle, a bootstrap-token
context field, and eight seeded bugs in the fixture so the self-check still proves the oracle healthy.
The fixture reimplements the auth API surface independently and shares no code with the real
implementation (VERIFY-1).

### Attacker pass (separate session)
A second session, whose job is to falsify the builder's probes rather than defend them, re-read all
seven and added four probes for gaps the first pass left untested, each with a seeded bug that proves
it can fail:

- `cross-tenant-session` (AUTH-2): a session minted on one tenant is refused on another tenant.
- `csrf-origin` (AUTH-2): a cookie write with a cross-origin `Origin`, or with neither `Origin` nor
  `Sec-Fetch-Site`, is refused; the same write with the tenant's own `Origin` or `Sec-Fetch-Site:
  same-origin` succeeds.
- `authority-matrix` (AUTH-3): member is refused on `GET /users`, `GET /api-keys` and granting owner;
  admin may list but not grant owner; owner may do all three.
- `key-revocation` (AUTH-4): `DELETE /api-keys/:id` revokes a key, and demoting its minter revokes it.

Five seeded bugs back these (`session-cross-tenant`, `csrf-ignored`, `member-can-list-users`,
`escalation-allowed`, `key-revocation-ignored`). The fixture also gained the `GET /users` and
`DELETE /api-keys/:id` routes and the CSRF check it was missing, so the clean fixture does not report
false positives. The self-check now proves 17/17 seeded bugs caught with no false positives. The pass
was run by a different session with the same models and harness; it is independence from the builder's
code, not from the builder's tooling.

## Decision
Accept the edits above and these design choices and limits, so each is a decision, not a silent gap:

1. **Bootstrap is the interim way in.** `POST /auth/bootstrap` creates the first owner of an empty
   tenant and needs `BULKHEAD_BOOTSTRAP_TOKEN`; the auth package treats a secret shorter than 32
   characters, or none, as bootstrap disabled. Phase 6 provisioning should create owners directly and
   bootstrap can then be removed. Check: `test:packages/auth/test/auth.test.ts::bootstrap`.
2. **Passwords use PBKDF2-SHA256 at 100,000 iterations**, the maximum Workers' WebCrypto allows. That
   is below current OWASP guidance for PBKDF2. Parameters are stored per hash so they can be raised
   or the scheme replaced without a flag day. Login is throttled per email (5 failures per 15
   minutes, per tenant); there is no per-IP throttle yet. Check: `test:packages/auth/test/auth.test.ts::passwords: salted PBKDF2`, `test:packages/auth/test/auth.test.ts::login: one answer`. No check: no black-box probe covers the login throttle or PBKDF2 parameters, and there is no per-IP throttle to check.
3. **Sessions**: 256-bit random token, only its SHA-256 stored, `__Host-` cookie (Secure, HttpOnly,
   Path=/, no Domain, SameSite=Lax), 7-day absolute and 24-hour idle lifetime. Login rotates;
   logout, role change and disable revoke. Cookie-authenticated writes also need a same-origin
   `Origin` or `Sec-Fetch-Site`; a write carrying neither is refused (a non-browser client presents a
   bearer key instead). Safari does not accept `Secure` cookies over plain-http localhost. Check: `probe:cookie-flags`, `probe:session-rotation`, `probe:csrf-origin`, `mutation:csrf-no-header-allowed`, `mutation:csrf-origin-ignored`, `mutation:cookie-not-httponly`, `test:packages/auth/test/auth.test.ts::sessions expire`.
4. **API keys**: `bkk_<id>_<secret>`, secret stored as a hash, shown once, never listable. A key
   carries a role (capped at its minter's role, re-capped at each use) and a permission list that
   must name permissions routes actually declare. Role change or disable of the minter revokes it. Check: `probe:api-key-scope`, `probe:key-revocation`, `mutation:key-permission-ignored`, `test:packages/auth/test/auth.test.ts::AUTH-4: keys are tenant-bound`.
5. **Role changes**: nobody grants or touches a role above their own, and the last owner cannot be
   demoted or disabled. Check: `probe:authority-matrix`, `mutation:grant-above-own-role`, `test:packages/auth/test/auth.test.ts::user management cannot escalate`.
6. **Auth tables are append-only schema steps** (`authSchema`), tracked by index, so apps pass
   `[...authSchema, ...theirs]`. Reordering would corrupt existing tenants. No check: nothing tests that the auth schema steps keep their order, so a reorder would only be caught by review; a migration-order test is owed.

Known limits, none of them silent:
- AUTH-4's "stored only as hashes" is not observable over HTTP; it is covered by unit tests that
  read the tenant database, not by a black-box probe. The spec's "storage inspector" does not exist yet.
- Not probed black-box: session absolute expiry and idle timeout, login throttling, last-owner
  protection, and API-key expiry. All are unit-tested.
- Not built: password reset, email verification, MFA, OAuth/SSO, session listing, audit trail.
- Durable Object `changes` is `rowsWritten` and counts index writes (one inserted user reads as 3).
  The first black-box run against workerd caught code that assumed 1; auth now confirms inserts by
  reading the row back, and the unit-test fake reports tripled counts so this cannot regress unseen.
- Mutation checks (VERIFY-4) were done by hand: breaking role-change revocation and key permission
  checks each failed the black-box run; further unit mutations were killed by the auth tests. Automated
  mutation checks remain later-phase work.
- Rules stay `proposed`; no attestation exists until Phase 7.

## Consequences
`pnpm gate:phase3` passes: typecheck, unit tests, spec lint, catalog check, verify self-check, route
manifest check, and a black-box run of TENANT-1/4/5 and AUTH-1..4 against the demo Worker in local
workerd. `gate:phase2` now runs the tenancy rules alone and no longer pulls in the auth probes;
`gate:phase3` adds the AUTH rule set on top, so the phase boundary is real. The CSRF check was also
mutated against the real Worker (origin comparison ignored; no-header fallback restored): each failed
`csrf-origin` and nothing else. Phase 4 (crypto) may begin; DR-0007 proposes its opening item.
