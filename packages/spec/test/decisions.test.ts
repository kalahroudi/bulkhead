import { test } from "node:test";
import assert from "node:assert/strict";
import { decisionItems, lintDecisionRecord } from "../src/index.ts";

const record = (decision: string, rules = "AUTH-2") => `# DR-9999: x\n\n- Status: proposed\n- Rules: ${rules}\n\n## Context\nwords\n\n## Decision\n${decision}\n\n## Consequences\n1. not a decision\n`;
const codes = (md: string) => lintDecisionRecord("DR-9999", md).map((i) => i.code);

test("a choice that cites a ref, or gives a reason, passes", () => {
  assert.deepEqual(codes(record("1. Cookies are Secure. Check: `probe:cookie-flags`.\n2. Reset is not built.\n   No check: password reset does not exist yet, so nothing can enforce it.")), []);
});

test("a choice with neither Check nor No check fails (the drift case)", () => {
  assert.deepEqual(codes(record("1. A write with no Origin is refused.")), ["unchecked-decision"]);
});

test("Check without a ref, a one-word No check, and an unknown ref kind all fail", () => {
  assert.deepEqual(codes(record("1. Thing. Check: it is covered.")), ["check-without-ref"]);
  assert.deepEqual(codes(record("1. Thing. No check: later.")), ["weak-no-check"]);
  assert.deepEqual(codes(record("1. Thing. Check: `vibes:good`.")), ["check-without-ref"]);
});

test("continuation lines belong to their item, and the next number starts a new one", () => {
  const p = decisionItems(record("1. First choice\n   continues here. Check: `test:a.test.ts::x`.\n2. Second. Check: `gate:phase4`."))!;
  assert.equal(p.items.length, 2);
  assert.deepEqual(p.items[0]!.refs, ["test:a.test.ts::x"]);
});

test("records without a Rules header, and prose-only decisions, have nothing to check", () => {
  assert.deepEqual(codes("# DR\n\n- Status: x\n\n## Decision\n1. nothing checked\n"), []);
  assert.deepEqual(codes(record("Prose only, no list.")), []);
});
