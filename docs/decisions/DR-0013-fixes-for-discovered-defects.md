# DR-0013: Fixes for defects found while building the mutation checks and the owed probes

- Status: proposed (owner acceptance and signature pending; the builder cannot accept its own record)
- Date: 2026-10-13
- Rules: TENANT-1, AUTH-1, AUTH-2, AUTH-4, BILL-2, VERIFY-3

## Context
Reviews and runs during Phase 4 found defects that were recorded as known limits (DR-0009, DR-0012) or reported by reviewers but not fixed. One was confirmed by running it: against an app with no billing routes, the verifier reports `FAIL BILL-2 forged-signature` and "1 confirmed finding(s)", so an absent feature is reported as a security finding. This record lists the fixes, made with the same split of roles as before: the verifier and spec edits (frozen paths) by a separate attacker session, the auth test and the scripts by the builder.

### Edits to frozen paths (`packages/verify/`, `packages/spec/src/formats.ts` comments)
A third probe outcome, "not applicable", used by `forged-signature` when the target has no billing routes; stronger `role-change-authority`, `listings-hide-secrets` and `key-wrong-secret-denied`; one seeded bug for the secret-length case; three comment corrections.

## Decision
1. **A missing feature is "not applicable", never a finding and never a pass.** A probe may report `skipped` with a reason; skipped probes are listed, are not findings, do not count towards rule coverage, and a run in which every selected probe was skipped exits non-zero because nothing was verified. Check: `test:packages/verify/test/verify.test.ts::a probe that does not apply`, `test:packages/verify/test/verify.test.ts::a run that verified nothing`.
2. **Probes that could be satisfied by another defence now carry a positive control or a wider scan.** `role-change-authority` first shows the same cookie can perform an allowed write; `listings-hide-secrets` also rejects any 64-hex string, any `pbkdf2-sha256$` hash and any 43-character base64url token; `key-wrong-secret-denied` also tries first-character, middle-character, truncated and extended secrets, backed by a seeded bug that only the new variants catch. Check: `probe:role-change-authority`, `probe:listings-hide-secrets`, `probe:key-wrong-secret-denied`, `mutation:user-list-leaks-password-hash`.
3. **The dummy password hash is tied to the real work factor.** The constant is exported and the test asserts the dummy's iteration count equals it, so raising one without regenerating the other fails. Check: `test:packages/auth/test/auth.test.ts::unknown-user login verifies against a well-formed constant hash`.
4. **The mutation runner copies no secrets files, cleans up on interrupt, and judges gaps by real test failures.** Secret-bearing files (`.dev.vars`, `.env*`, `.npmrc`) are left out of the scratch copy; Ctrl-C and termination remove it; every edit of a multi-edit mutation must match exactly once at the moment it is applied; a gap counts as killed only by a failing test, never by a crash or syntax error. Check: `script:scripts/mutation-selfcheck.ts`, `gate:phase4`.
5. **Comments that claimed unbuilt things as planned, or misdescribed what exists, are corrected.** No check: comment text has no behaviour to test.

## Consequences
`gate:phase4` is unchanged in shape. Known limits that remain are listed in DR-0009 and DR-0012; this record closes the verifier false finding, the three weak-probe notes, the dummy-hash coupling and the runner robustness items. A green report means no known leak paths, not proof of none.
