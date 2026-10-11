# DR-0006: Phase 3 auth: core hook change, verify additions, known limits

- Status: proposed (owner acceptance and signature pending; the builder cannot accept its own record)
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
context field, and eight seeded bugs in the fixture so the self-check still proves the oracle healthy
(12/12 caught, no false positives). The fixture reimplements the auth API surface independently and
shares no code with the real implementation (VERIFY-1). The separate attacker pass over these
probes is still owed; this record does not substitute for it.

## Decision
Accept the edits above and these design choices and limits, so each is a decision, not a silent gap:

1. **Bootstrap is the interim way in.** `POST /auth/bootstrap` creates the first owner of an empty
   tenant and needs `BULKHEAD_BOOTSTRAP_TOKEN` (32+ chars; shorter or absent disables it). Phase 6
   provisioning should create owners directly and bootstrap can then be removed.
2. **Passwords use PBKDF2-SHA256 at 100,000 iterations**, the maximum Workers' WebCrypto allows. That
   is below current OWASP guidance for PBKDF2. Parameters are stored per hash so they can be raised
   or the scheme replaced without a flag day. Login is throttled per email (5 failures per 15
   minutes, per tenant); there is no per-IP throttle yet.
3. **Sessions**: 256-bit random token, only its SHA-256 stored, `__Host-` cookie (Secure, HttpOnly,
   Path=/, no Domain, SameSite=Lax), 7-day absolute and 24-hour idle lifetime. Login rotates;
   logout, role change and disable revoke. Cookie-authenticated writes also need a same-origin
   `Origin` or `Sec-Fetch-Site`. Safari does not accept `Secure` cookies over plain-http localhost.
4. **API keys**: `bkk_<id>_<secret>`, secret stored as a hash, shown once, never listable. A key
   carries a role (capped at its minter's role, re-capped at each use) and a permission list that
   must name permissions routes actually declare. Role change or disable of the minter revokes it.
5. **Role changes**: nobody grants or touches a role above their own, and the last owner cannot be
   demoted or disabled.
6. **Auth tables are append-only schema steps** (`authSchema`), tracked by index, so apps pass
   `[...authSchema, ...theirs]`. Reordering would corrupt existing tenants.

Known limits, none of them silent:
- AUTH-4's "stored only as hashes" is not observable over HTTP; it is covered by unit tests that
  read the tenant database, not by a black-box probe. The spec's "storage inspector" does not exist yet.
- Not probed black-box: expiry and idle timeout, CSRF origin checks, login throttling, last-owner
  protection, key expiry and revocation. All are unit-tested.
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
workerd. Phase 4 (crypto) may begin once the owner accepts this record.
