import { test } from "node:test";
import assert from "node:assert/strict";
import { GENESIS_PREV, lintSpec, spec, validateEvent, validateFinding, type Rule } from "../src/index.ts";

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

test("event: genesis uses zero prev, signature required", () => {
  const ev = { format: "bulkhead.event/1", seq: 0, prev: GENESIS_PREV, type: "verify.run", producer: "verify", at: "2026-10-11T00:00:00Z", data: {}, hash: h("d"), signature: "sig" };
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
