# Contributing

**The verify gate:** a change is real only when `verify` passes and an attestation is signed. A feature that has not passed verify is not done, regardless of what the code looks like.

1. Propose a rule (ID, reason, enforcement, tier) in `packages/spec/src/rules.ts`.
2. Write the failing check first. Invariant and contract tiers need the owner's approval before implementation.
3. Implement until the check passes.
4. Never use `--no-verify`. Changes to frozen paths (`FROZEN_PATHS`) need an accepted decision record in `docs/decisions/`.

Run `pnpm gate:phase0` before pushing. Licensed under Apache-2.0.
