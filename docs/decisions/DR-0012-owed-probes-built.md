# DR-0012: Owed auth probes built; unknown-email login bug found and fixed

- Status: proposed (owner acceptance and signature pending; the builder cannot accept its own record)
- Date: 2026-10-13
- Rules: AUTH-1, AUTH-2, AUTH-3, AUTH-4, TENANT-1

## Context
DR-0009 listed black-box probes owed for lines that only unit tests protected. An attacker session (separate agent, `packages/verify/` only) built them. While doing so it found a real bug that no test caught: `POST /auth/login` for an unknown email returned 500 on workerd, so unknown and wrong-password answers differed and registered emails could be enumerated. Cause: the dummy password hash was computed with `hashPassword()` at module scope, which workerd forbids outside a request, and the rejected promise was cached. The auth unit tests use a fake and could not see it.

### Edits to `packages/verify/` (frozen, authorised by DR-0007)
Probes: `key-wrong-secret-denied`, `bootstrap-token-required`, `bootstrap-claims-once`, `role-change-authority`, `key-role-ceiling`, `listings-hide-secrets`, `unknown-email-login-same-answer`; `identity-header-differential` now tries seven client-supplied tenant inputs. Nine seeded bugs back them (self-check 27/27, no false positives). The catalog gained `tenant-from-forwarded-host` and `unknown-user-dummy-at-module-scope`; seven gap entries were promoted to probes, so only the two `disabled` shadowing gaps and `tenant-binding-check-removed` remain.

### Edit outside frozen paths
`packages/auth/src/secrets.ts` uses a precomputed constant `DUMMY_HASH` (same PBKDF2 work, no randomness, no shared promise).

## Decision
1. **The unknown-email fix is a constant hash, not a lazy one.** A lazy promise shared across requests risks cross-request I/O errors in workerd; a constant has no such failure mode and keeps timing equal. Check: `probe:unknown-email-login-same-answer`, `mutation:unknown-user-dummy-at-module-scope`, `test:packages/auth/test/auth.test.ts::unknown-user login verifies against a well-formed constant hash`.
2. **Every probe an attacker adds ships with a seeded bug and a catalog entry,** and existing entries whose real mutation now also fails a new probe get that probe added to their expected set only with a stated reason (shared database collides setup). Check: `test:packages/verify/test/mutations.test.ts::DR-0007 item 4`, `gate:phase4`.
3. **Remaining weaknesses, recorded:** `listings-hide-secrets` scans for named needles only; `key-wrong-secret-denied` does not catch a compare that checks only a prefix; `role-change-authority` covers admin acting on higher roles, not members. No check: each needs a stronger oracle, which is future probe work, not a defect in what exists.

## Consequences
`gate:phase4` runs 29 mutations. Rules stay `proposed`. A green report means no known leak paths, not proof of none.
