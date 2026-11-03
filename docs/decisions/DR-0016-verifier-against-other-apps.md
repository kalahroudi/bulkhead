# DR-0016: Running the verifier against an app other than the demo: state the contract the probes assume, and make a missing piece UNVERIFIED, never a pass

- Status: proposed (owner decision and signature pending; the builder cannot accept its own record)
- Date: 2026-11-03
- Rules: TENANT-1, TENANT-4, TENANT-5, AUTH-1, AUTH-2, AUTH-3, AUTH-4, ROUTE-1, CRYPTO-1, CRYPTO-2

## Context
The next item in the agreed order is making the verifier usable against an app other than `examples/demo-app`. Transport is already generic: `bulkhead-verify run --target <url> --persist-dir <dir> --route-manifest <file>` takes any local or registered URL, and the DR-0011 spike showed a second app can be driven through `scripts/verify-kernel.ts --app` and `scripts/verify-mutations.ts`. What is not generic is what the probes assume about the app behind the URL. Counting path literals in `packages/verify/src/probes.ts`: `/notes` (34 uses), `/private/member`, `/private/admin`, `/private/owner`, `/api-keys`, `/users`, `/whoami`, `/summary`, `/secrets`, `/webhooks/billing`, `/plan`, `/auth/login`, `/auth/bootstrap`, `/auth/logout`, `/admin/shred`, `/admin/rotate-key`. The probes also assume the hostname form `<tenant>.demo.localhost`, the cookie name `__Host-bk_session`, the roles owner/admin/member, a bootstrap token supplied as `BULKHEAD_VERIFY_BOOTSTRAP_TOKEN`, and a webhook secret fixed in the verifier. An app that follows the structure but names its routes differently would today either fail probes for the wrong reason or, worse, have a probe that finds nothing to attack and reports a pass.

This record does not change what any rule requires. It covers how the verifier learns what an app offers and how it behaves when the app offers less than the demo.

## Decision

1. **Write the contract down before generalising it.** Add `docs/verify-target-contract.md`, generated from nothing and checked by a test: one table listing every route, header, cookie, role and environment value the probes use, with the probe ids that use each. The test extracts path literals from `probes.ts` and fails if one is missing from the table, so the document cannot go stale silently. The demo is the reference implementation of the contract; no probe changes in this step.
   No check: not yet built; the guard test (contract.test.ts) does not exist; it is the first deliverable of the attacker session this record commissions, and this record is amended with its ref when it lands.

2. **A missing route is UNVERIFIED, not a pass.** Before a probe runs, it declares the manifest routes it needs. If the target's committed manifest lacks one, the result is `unverified` with the missing route named, which already makes the run NOT GREEN (exit 3). Probes that already do this for CRYPTO (`hasStoreRoute`) are the pattern; the rest follow it. A probe whose attack is vacuous because the route is absent must never reach its assertion.
   No check: not yet built; a mutation entry cannot cover this (a mutation changes app code, not the manifest), so the check is owed as a unit test per probe that runs it against a manifest with the route removed and expects `unverified` (missing-route.test.ts, attacker session); this record is amended with its ref when it lands.

3. **Configuration that is demo-specific becomes explicit flags with the demo's values as defaults.** Cookie name, tenant host suffix, and the webhook secret become fields of the target environment (`TargetEnv`), set from CLI flags and from a small committed `verify-target.json` next to the route manifest. Defaults keep the demo's behaviour byte for byte. Role names and the route paths of decision 1 stay fixed: an app that wants to be verified implements those, because renaming them would make the probes configurable enough to be pointed at nothing.
   Check: `gate:phase4` runs unchanged and must stay green. No check yet that a changed cookie name or host suffix reaches the probes: that test (target-env.test.ts) is owed by the attacker session.

4. **Prove it with a second app that is not a copy.** Add a minimal `examples/contract-app` (builder) that implements the contract with different internals (it may reuse `@kalahroudi/bulkhead-auth` but must have its own schema, table names and handler layout) and run `gate:phase4` probes against it. If every probe passes without edits, the contract is real; if one needs an edit, the contract table is wrong and decision 1 is revisited. The mutation runner is not extended to it in this step: mutating a second app multiplies the catalog without testing the verifier any further than the DR-0011 entries already did.
   Check: `script:scripts/verify-kernel.ts` (its `--app` run against `examples/contract-app` is added to `gate:phase4` in that step).

5. **The `--app` launcher stays a development harness.** `scripts/verify-kernel.ts` starts workerd with `wrangler dev`, a fresh bootstrap token and a fresh master key. Pointing the verifier at a deployed app is the registered-environment path (`checkTarget`), unchanged by this record; a deployed app has no `--persist-dir`, so CRYPTO-1 and CRYPTO-2 are UNVERIFIED there by design (DR-0010 choice 7).
   No check: this decision only states a boundary; the behaviour it describes is already covered by the CRYPTO UNVERIFIED tests.

## Consequences
- Steps 1 to 3 edit `packages/verify/`, so they belong to an attacker session. Step 4 is builder work and needs the contract table first.
- The contract table will record what the demo does, including its accidents. Some entries may be demo choices that the owner wants dropped from the contract rather than frozen into it; those come back as amendments to this record.
- A green run against a second app still means no known leak paths in the cases written down, not proof.
