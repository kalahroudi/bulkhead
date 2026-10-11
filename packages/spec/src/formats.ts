import { ORACLES, type Oracle } from "./types.ts";

// Format definitions: data classification, decision records, attestations, events.
// Types plus structural validators only. Hashing, signing and chain verification arrive in Phase 1+.

export type Result<T> = { ok: true; value: T } | { ok: false; errors: string[] };

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

function done<T>(errors: string[], value: unknown): Result<T> {
  return errors.length ? { ok: false, errors } : { ok: true, value: value as T };
}

// --- Data classification ---

/** Fail closed: a field with no class is "unclassified", and verify does not go green while any exist. */
export const DATA_CLASSES = ["public", "internal", "personal", "sensitive", "secret"] as const;
export type DataClass = (typeof DATA_CLASSES)[number];

/** Classes that must pass through the crypto port and never reach storage as plaintext. */
export const ENCRYPTED_CLASSES: readonly DataClass[] = ["sensitive", "secret"];

export interface FieldClassification {
  table: string;
  field: string;
  class: DataClass;
  /** Secrets are write-only: no API may return them (CRYPTO-5). */
  writeOnly?: boolean;
}

export interface ClassificationSchema {
  version: 1;
  fields: FieldClassification[];
}

export function validateClassification(input: unknown): Result<ClassificationSchema> {
  const errors: string[] = [];
  if (!isObj(input)) return { ok: false, errors: ["classification must be an object"] };
  if (input.version !== 1) errors.push("version must be 1");
  const seen = new Set<string>();
  if (!Array.isArray(input.fields)) errors.push("fields must be an array");
  else
    input.fields.forEach((f, i) => {
      if (!isObj(f)) return errors.push(`fields[${i}] must be an object`);
      if (!isStr(f.table)) errors.push(`fields[${i}].table required`);
      if (!isStr(f.field)) errors.push(`fields[${i}].field required`);
      if (!DATA_CLASSES.includes(f.class as DataClass))
        errors.push(`fields[${i}].class must be one of ${DATA_CLASSES.join(", ")}`);
      if (f.class === "secret" && f.writeOnly !== true) errors.push(`fields[${i}]: secret fields must be writeOnly`);
      const key = `${String(f.table)}.${String(f.field)}`;
      if (seen.has(key)) errors.push(`duplicate classification for ${key}`);
      seen.add(key);
    });
  return done(errors, input);
}

// --- Decision record ---

export const DECISION_STATUS = ["proposed", "accepted", "rejected", "superseded"] as const;
export type DecisionStatus = (typeof DECISION_STATUS)[number];

export interface DecisionRecord {
  /** `DR-NNNN` */
  id: string;
  title: string;
  status: DecisionStatus;
  date: string;
  context: string;
  decision: string;
  consequences: string;
  /** Rules this decision touches. Required when a frozen path or an invariant/contract rule is affected. */
  rules: string[];
  supersedes?: string;
  /** Signature by the human key on accepted records. */
  signature?: string;
}

export function validateDecisionRecord(input: unknown): Result<DecisionRecord> {
  const errors: string[] = [];
  if (!isObj(input)) return { ok: false, errors: ["decision record must be an object"] };
  if (typeof input.id !== "string" || !/^DR-\d{4}$/.test(input.id)) errors.push("id must match DR-NNNN");
  for (const k of ["title", "context", "decision", "consequences"]) if (!isStr(input[k])) errors.push(`${k} required`);
  if (!DECISION_STATUS.includes(input.status as DecisionStatus)) errors.push("invalid status");
  if (typeof input.date !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(input.date)) errors.push("date must be YYYY-MM-DD");
  if (!Array.isArray(input.rules) || !input.rules.every(isStr)) errors.push("rules must be an array of rule IDs");
  if (input.status === "accepted" && !isStr(input.signature)) errors.push("accepted records need a human signature");
  return done(errors, input);
}

// --- Attestation ---

/** A signed result bound to the exact build. Any change to a bound hash invalidates it (GATE-1). */
export interface Attestation {
  format: "bulkhead.attestation/1";
  treeHash: string;
  specHash: string;
  specVersion: string;
  verifyVersion: string;
  catalogHash: string;
  /** Verify run summary. */
  result: { passed: boolean; seededBugsFound: number; seededBugsTotal: number; openConfirmedFindings: number };
  /** Reports must carry the honest-limits statement (SPEC-4). */
  limits: string;
  issuedAt: string;
  /** Signature by the human key. */
  signature: string;
}

export function validateAttestation(input: unknown): Result<Attestation> {
  const errors: string[] = [];
  if (!isObj(input)) return { ok: false, errors: ["attestation must be an object"] };
  if (input.format !== "bulkhead.attestation/1") errors.push("format must be bulkhead.attestation/1");
  for (const k of ["treeHash", "specHash", "catalogHash"])
    if (typeof input[k] !== "string" || !SHA256.test(input[k])) errors.push(`${k} must be sha256:<64 hex>`);
  for (const k of ["specVersion", "verifyVersion", "limits", "signature"]) if (!isStr(input[k])) errors.push(`${k} required`);
  if (typeof input.issuedAt !== "string" || !ISO.test(input.issuedAt)) errors.push("issuedAt must be ISO-8601 UTC");
  const r = input.result;
  if (!isObj(r)) errors.push("result required");
  else {
    if (typeof r.passed !== "boolean") errors.push("result.passed must be boolean");
    for (const k of ["seededBugsFound", "seededBugsTotal", "openConfirmedFindings"])
      if (!Number.isInteger(r[k]) || (r[k] as number) < 0) errors.push(`result.${k} must be a non-negative integer`);
    if (r.passed === true) {
      if (r.seededBugsFound !== r.seededBugsTotal) errors.push("a passing result requires all seeded bugs found (VERIFY-3)");
      if (r.openConfirmedFindings !== 0) errors.push("a passing result cannot have open confirmed findings (VERIFY-6)");
    }
  }
  return done(errors, input);
}

// --- Findings ---

/** Only an oracle can confirm a finding. A human may reject one with a reason; it keeps its reproduction (VERIFY-2). */
export const FINDING_VERDICTS = ["confirmed", "needs_validation", "fixed", "rejected"] as const;
export type FindingVerdict = (typeof FINDING_VERDICTS)[number];

export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type Severity = (typeof SEVERITIES)[number];

export interface Finding {
  /** `F-NNN` */
  id: string;
  title: string;
  verdict: FindingVerdict;
  /** Absent for needs_validation and rejected findings: no severity without a confirmation. */
  severity?: Severity;
  /** Rule that was broken, if any. A confirmed finding mapping to no rule becomes a proposed rule. */
  ruleId?: string;
  oracle: Oracle;
  /** Exact steps or request that reproduce it. Required for confirmed findings. */
  reproduction?: string;
  replays?: { passed: number; total: number };
  /** Permanent regression scenario (`RS-NNNN`) created when a finding is confirmed. */
  regressionId?: string;
  /** For needs_validation: the exact unresolved fact. */
  unresolvedFact?: string;
  /** Rejection reason, required when rejected. */
  rejectionReason?: string;
  source: "black-box" | "gray-box";
}

export function validateFinding(input: unknown): Result<Finding> {
  const errors: string[] = [];
  if (!isObj(input)) return { ok: false, errors: ["finding must be an object"] };
  if (typeof input.id !== "string" || !/^F-\d{3,}$/.test(input.id)) errors.push("id must match F-NNN");
  if (!isStr(input.title)) errors.push("title required");
  if (!FINDING_VERDICTS.includes(input.verdict as FindingVerdict)) errors.push("invalid verdict");
  if (!ORACLES.includes(input.oracle as Oracle)) errors.push("oracle must be one of the five deterministic oracles");
  if (input.source !== "black-box" && input.source !== "gray-box") errors.push("source must be black-box or gray-box");
  if (input.severity !== undefined && !SEVERITIES.includes(input.severity as Severity)) errors.push("invalid severity");
  if (input.verdict === "confirmed") {
    if (!isStr(input.reproduction)) errors.push("confirmed findings need a reproduction");
    if (input.severity === undefined) errors.push("confirmed findings need a severity");
    if (typeof input.regressionId !== "string" || !/^RS-\d{4}$/.test(input.regressionId))
      errors.push("confirmed findings need a regressionId (RS-NNNN)");
  }
  if (input.verdict === "needs_validation") {
    if (!isStr(input.unresolvedFact)) errors.push("needs_validation findings need the exact unresolved fact");
    if (input.severity !== undefined) errors.push("needs_validation findings carry no severity");
  }
  if (input.verdict === "rejected" && !isStr(input.rejectionReason)) errors.push("rejected findings need a reason");
  return done(errors, input);
}

// --- Events ---

export const EVENT_TYPES = [
  "commit.scan",
  "verify.run",
  "finding.recorded",
  "review.requested",
  "review.signed",
  "agent.blocked",
  "agent.question",
  "fleet.run",
  "attestation.issued",
  "deploy.checked",
] as const;
export type EventType = (typeof EVENT_TYPES)[number];

/** Append-only, hash-chained, signed by the producing tool. Unsigned producers are untrusted (PLANE-2). */
export interface BulkheadEvent {
  format: "bulkhead.event/1";
  /** Position in the chain, starting at 0. */
  seq: number;
  /** Hash of the previous event; the genesis event uses 64 zero hex digits. */
  prev: string;
  type: EventType;
  /** Tool that produced the event, e.g. `verify`, `cli`, `hook`. */
  producer: string;
  at: string;
  data: Record<string, unknown>;
  /** Hash over the canonical form of every field above. */
  hash: string;
  /** Producer signature over `hash`. */
  signature: string;
}

export const GENESIS_PREV = `sha256:${"0".repeat(64)}`;

export function validateEvent(input: unknown): Result<BulkheadEvent> {
  const errors: string[] = [];
  if (!isObj(input)) return { ok: false, errors: ["event must be an object"] };
  if (input.format !== "bulkhead.event/1") errors.push("format must be bulkhead.event/1");
  if (!Number.isInteger(input.seq) || (input.seq as number) < 0) errors.push("seq must be a non-negative integer");
  for (const k of ["prev", "hash"]) if (typeof input[k] !== "string" || !SHA256.test(input[k])) errors.push(`${k} must be sha256:<64 hex>`);
  if (input.seq === 0 && input.prev !== GENESIS_PREV) errors.push("genesis event must use the zero prev hash");
  if (!EVENT_TYPES.includes(input.type as EventType)) errors.push("unknown event type");
  if (!isStr(input.producer)) errors.push("producer required");
  if (typeof input.at !== "string" || !ISO.test(input.at)) errors.push("at must be ISO-8601 UTC");
  if (!isObj(input.data)) errors.push("data must be an object");
  if (!isStr(input.signature)) errors.push("signature required (unsigned events are untrusted, PLANE-2)");
  return done(errors, input);
}
