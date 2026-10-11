import { test } from "node:test";
import assert from "node:assert/strict";
import {
  GENESIS_PREV,
  lintSpec,
  spec,
  validateAttestation,
  validateClassification,
  validateDecisionRecord,
  validateEvent,
  validateFinding,
  type Rule,
} from "../src/index.ts";

const h = (c: string) => `sha256:${c.repeat(64)}`;

test("shipped spec lints clean", () => {
  assert.deepEqual(lintSpec(spec), []);
});

test("every shipped rule starts as proposed", () => {
  assert.ok(spec.rules.every((r) => r.state === "proposed"));
});

test("linter catches duplicate IDs, missing fields, bad tier and shared scenarios", () => {
  const base = spec.rules[0] as Rule;
  const bad = [
    base,
    { ...base },
    { ...(spec.rules[1] as Rule), reason: " ", tier: "optional" as never, scenario: base.scenario },
    { ...(spec.rules[2] as Rule), id: "nope", scenario: "Bad Name" },
  ];
  const codes = lintSpec({ version: "0.1.0", rules: bad }).map((i) => i.code);
  for (const c of ["duplicate-id", "missing-reason", "bad-tier", "duplicate-scenario", "bad-id", "bad-scenario"])
    assert.ok(codes.includes(c), `expected ${c}, got ${codes.join(",")}`);
});

test("classification: secrets must be write-only, duplicates rejected", () => {
  assert.equal(validateClassification({ version: 1, fields: [{ table: "t", field: "f", class: "secret" }] }).ok, false);
  assert.equal(validateClassification({ version: 1, fields: [{ table: "t", field: "f", class: "secret", writeOnly: true }] }).ok, true);
  assert.equal(
    validateClassification({ version: 1, fields: [{ table: "t", field: "f", class: "public" }, { table: "t", field: "f", class: "public" }] }).ok,
    false,
  );
});

test("decision record: accepted needs a signature", () => {
  const dr = { id: "DR-0001", title: "t", status: "accepted", date: "2026-10-11", context: "c", decision: "d", consequences: "q", rules: [] };
  assert.equal(validateDecisionRecord(dr).ok, false);
  assert.equal(validateDecisionRecord({ ...dr, signature: "sig" }).ok, true);
});

const attestation = {
  format: "bulkhead.attestation/1",
  treeHash: h("a"), specHash: h("b"), catalogHash: h("c"),
  specVersion: "0.1.0", verifyVersion: "0.0.1",
  result: { passed: true, seededBugsFound: 3, seededBugsTotal: 3, openConfirmedFindings: 0 },
  limits: "No known leak paths; not proof of none.",
  issuedAt: "2026-10-11T00:00:00Z", signature: "sig",
};

test("attestation: valid passes; missed seeded bug or open finding cannot pass", () => {
  assert.equal(validateAttestation(attestation).ok, true);
  assert.equal(validateAttestation({ ...attestation, result: { ...attestation.result, seededBugsFound: 2 } }).ok, false);
  assert.equal(validateAttestation({ ...attestation, result: { ...attestation.result, openConfirmedFindings: 1 } }).ok, false);
  assert.equal(validateAttestation({ ...attestation, treeHash: "abc" }).ok, false);
});

test("event: genesis uses zero prev, signature required", () => {
  const ev = { format: "bulkhead.event/1", seq: 0, prev: GENESIS_PREV, type: "commit.scan", producer: "hook", at: "2026-10-11T00:00:00Z", data: {}, hash: h("d"), signature: "sig" };
  assert.equal(validateEvent(ev).ok, true);
  assert.equal(validateEvent({ ...ev, prev: h("1") }).ok, false);
  assert.equal(validateEvent({ ...ev, signature: "" }).ok, false);
  assert.equal(validateEvent({ ...ev, type: "nope" }).ok, false);
});

test("finding: confirmed needs reproduction, severity and regression; needs_validation has no severity", () => {
  const f = { id: "F-014", title: "x", verdict: "confirmed", severity: "high", oracle: "canary", source: "black-box", reproduction: "steps", regressionId: "RS-0412" };
  assert.equal(validateFinding(f).ok, true);
  assert.equal(validateFinding({ ...f, reproduction: undefined }).ok, false);
  assert.equal(validateFinding({ ...f, oracle: "llm" }).ok, false);
  const nv = { id: "F-015", title: "y", verdict: "needs_validation", oracle: "canary", source: "black-box", unresolvedFact: "prod cache config" };
  assert.equal(validateFinding(nv).ok, true);
  assert.equal(validateFinding({ ...nv, severity: "low" }).ok, false);
  assert.equal(validateFinding({ id: "F-016", title: "z", verdict: "rejected", oracle: "spec", source: "black-box" }).ok, false);
});
