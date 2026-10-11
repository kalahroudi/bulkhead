/** invariant: never changes. contract: changes by proposal and human sign-off. default: agents may change freely. */
export const TIERS = ["invariant", "contract", "default"] as const;
export type Tier = (typeof TIERS)[number];

/** A rule moves strictly forward through these states. The check is approved before the implementation exists. */
export const LIFECYCLE = ["proposed", "checkable", "implemented", "verified", "live"] as const;
export type Lifecycle = (typeof LIFECYCLE)[number];

/** Which of the nine principles a rule serves (1-9, see the architecture document). */
export type Principle = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9;

/** The five deterministic oracles. Only these issue verdicts. */
export const ORACLES = ["spec", "canary", "metamorphic", "differential", "state"] as const;
export type Oracle = (typeof ORACLES)[number];

export interface Rule {
  /** `AREA-N`, uppercase area, positive integer. Never reused once assigned. */
  id: string;
  /** One sentence stating what must hold. */
  statement: string;
  /** Why the rule exists. */
  reason: string;
  /** How the rule is enforced: structural (unrepresentable), startup check, hook, or verify scenario. */
  enforcement: string;
  tier: Tier;
  state: Lifecycle;
  principle: Principle;
  /** Oracle that decides the verdict for this rule's scenario. */
  oracle: Oracle;
  /** Stub name of the verify scenario, `pack/scenario-name`. The scenario is written in Phase 1+. */
  scenario: string;
}

export interface SpecDocument {
  /** Semver of the spec itself. An attestation names the spec version it was issued against. */
  version: string;
  rules: readonly Rule[];
}

export interface LintIssue {
  ruleId: string;
  code: string;
  message: string;
}
