# DR-0017: Phase 5 billing scoping (BILL-1..3): where the logic lives, what the demo gets, and the order of work

- Status: proposed (owner decision and signature pending; the builder cannot accept its own record)
- Date: 2026-11-04
- Rules: BILL-1, BILL-2, BILL-3, TENANT-1, TENANT-5, AUTH-3, LIFE-1

## Context
All three BILL rules are `proposed` and only part of one has a probe. `forged-signature` (BILL-2) exists, runs against the verify fixture, and is skipped as not applicable on the demo and contract-app, which have no billing routes (DR-0016 records that exemption). What the spec already decides:
- BILL-1: idempotency, entitlements and tenancy are owned by the core; a billing adapter only translates provider events into canonical billing events. The conformance check is an adapter suite.
- BILL-2: a webhook with an invalid signature, a replayed ID or a mismatched tenant is rejected, so it cannot change entitlements.
- BILL-3: a downgrade removes access to features outside the new plan immediately.

The spec does not decide: the canonical event shape, where entitlement state is stored, how a route declares the feature it needs, or what the adapter conformance suite checks. `packages/core` is frozen to the builder, so any of this that lives in core needs an accepted record before code, which is the reason for this one.

## Decision
1. **Entitlements live in the tenant's own Durable Object, not in the control plane.** One table, `entitlements(feature, granted_at)`, plus a `billing_events(event_id, applied_at)` table for idempotency, both created by core in every tenant's schema. A webhook resolves its tenant from the hostname like every other request (TENANT-1), never from the event body; an event whose body names another tenant is rejected, which is the "mismatched tenant" case. Keeping state per tenant means a billing bug cannot cross tenants by construction.
   Check: `probe:forged-signature`. No check for the storage placement itself: it is a design choice that the TENANT probes already police at the handle.
2. **Canonical event, three kinds.** `plan.changed {plan}`, `subscription.canceled`, `subscription.restored`, each with `eventId` and `occurredAt`. The core owns signature verification of the canonical envelope (HMAC-SHA256 over the raw body, constant-time compare, bounded timestamp skew), the replay table, and the plan-to-features mapping. An adapter (Stripe first, later others) is a pure function from a provider payload to a canonical event and may not touch storage. Out-of-order delivery is resolved by `occurredAt`: an older event is recorded as seen and changes nothing.
   Check: `probe:forged-signature`. No check: not yet built; the replay and out-of-order cases need new probes, which are step (a) of decision 5.
3. **A route declares the feature it needs.** The route policy gains an optional `feature`; the gate denies with 402 when the tenant lacks it, after role and permission, before the handler. A downgrade rewrites the entitlements table in the same event application, so the next request is already denied (BILL-3). The route manifest records the feature, so lowering it is visible to the owner like any policy change (ROUTE-3).
   No check: not yet built; the downgrade probe and a manifest case are step (a) of decision 5.
4. **The demo gets billing routes, so BILL-2 stops being skipped.** `GET /plan`, `POST /webhooks/billing`, and one feature-gated route (`GET /pro/report`, feature `reports`) are added to `examples/demo-app` and `examples/contract-app` with the same contract; the verify target contract gains them as required for BILL probes. The test webhook secret stays the registered-environment value (`whsec_fixture`), supplied as a var.
   Check: `gate:phase4` (BILL-2 must run, not skip, on both apps once built).
5. **Probes first, then code, in this order.** (a) Fixture and failing probes for replay, mismatched tenant, out-of-order, stale-timestamp and downgrade-revokes, each with seeded bugs and mutation entries (attacker session, no implementation). (b) Core: tables, envelope verification, replay, entitlement gate, `feature` policy. (c) Demo routes and the Stripe adapter with its conformance suite. (d) Review by a separate agent and the full gate for each step. Each step is its own PR.
   No check: this is sequencing of work, and each step is gated by its own PR, full gate and review.
6. **Honest limits.** The test secret and timestamp skew protect against forged and replayed deliveries, not against a provider-side compromise or a leaked signing secret; the webhook secret is a Worker secret like the master key. Entitlement checks are only as good as the feature names routes declare; a route with no `feature` is available on every plan. Provider-specific behaviour (retries, partial refunds, proration) is out of scope until an adapter is written.
   No check: statement of limits.

## Questions for the owner
- Is Stripe the only first adapter, or is the canonical event enough for now (adapter later)? I recommend core plus the canonical event first, adapter as the last step.
- Is per-tenant entitlement storage acceptable, given that a plan lookup across all tenants (reporting) then needs the control plane to be told separately? I recommend yes: reporting is not a security path and can be fed by an event later.

## Consequences
- Accepting this record unlocks step (a) only: probes, fixture and failing tests with no implementation. Step (b) edits `packages/core`, which needs this record accepted and signed.
- BILL rules stay `proposed` until Phase 7.
- A green run still means no known leak paths in the cases written down, not proof.
