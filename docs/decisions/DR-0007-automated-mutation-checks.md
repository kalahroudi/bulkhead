# DR-0007: Automate mutation checks as the first item of Phase 4

- Status: proposed (owner acceptance and signature pending; the builder cannot accept its own record)
- Date: 2026-10-12
- Rules: VERIFY-4 (and, through it, every rule with a probe)

## Context
VERIFY-4 says a scenario that still passes when the code it covers is deliberately broken is worthless.
Through Phases 2 and 3 this was checked by hand: break the code, expect the named probe to fail, revert.
Doing so found real gaps (a `disabled` check no test exercised, a CSRF fallback weaker than the recorded
decision), so the practice works, but a manual check protects nothing once the session ends. Each new
phase adds probes whose ability to fail is only as proven as the last person who remembered to try.

## Decision
Make mutation checking part of the gate, and do it before any Phase 4 feature work:

1. **A mutation catalog** lives next to the seeded-bug catalog: each entry names a file, a textual
   mutation (an exact-match replacement that must apply, otherwise the check errors rather than skipping),
   and the probe ids that must fail. A mutation that applies but fails no probe flags that scenario
   worthless; a mutation that fails an unexpected probe flags a mis-attributed one.
2. **The runner mutates a scratch copy** of the workspace, never the working tree, and boots the demo
   Worker in workerd against it, as `scripts/verify-kernel.ts` already does. The working tree is
   never edited, so an interrupted run cannot leave broken code behind.
3. **Seed the catalog with every mutation already proven by hand** (role-change revocation, key
   permission check, origin comparison, no-header CSRF fallback, `disabled` checks, login rotation),
   so the first run is a regression test of the practice itself.
4. **Gate:** `gate:phase4` runs the catalog. A phase cannot be accepted with a catalog entry that
   applied and survived. New probes in a phase must arrive with at least one catalog entry.
5. **Decision records get checks:** each numbered design choice in a DR that names a rule must either
   cite the probe or test that enforces it, or say why none can exist yet. A lint in the spec package
   fails otherwise, so a recorded decision cannot silently drift from the code (the CSRF fallback case).

Edits touch `packages/verify/` (catalog, runner) and `packages/spec/` (DR lint), both frozen, so they
need this record accepted first and a separate attacker session to review the catalog.

## Consequences
- Gate time grows by one workerd boot per mutation batch; mutations that hit unrelated probes can share
  a boot. Estimate: a few minutes, acceptable for a phase gate, too slow for every commit.
- It does not prove correctness. A mutation catalog covers only mutations someone wrote down, so it
  tightens VERIFY-4 without replacing review. A green report still means no known leak paths.
- Items still waiting on separate decisions, to be raised as their own records in Phase 4: a
  harness-side storage inspector (AUTH-4 hashes at rest, CRYPTO-1); a launch-time test profile for
  session, key and lockout windows (expiry, idle, throttle clearing; fail-closed, never a route); a
  generalised role-differential oracle (last-owner protection); and a spec rule for login throttling,
  which only the owner can add.
