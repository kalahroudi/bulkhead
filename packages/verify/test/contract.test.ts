// DR-0016 decision 1: docs/verify-target-contract.md must list everything the probes use. The doc cannot go stale silently.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { probes } from "../src/probes.ts";

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const source = readFileSync(here("../src/probes.ts"), "utf8");
const doc = readFileSync(here("../../../docs/verify-target-contract.md"), "utf8");

/** Path literals in probes.ts: a quoted string that starts with "/" and a letter. `${...}` becomes `:id`, a query string is dropped. */
export function pathLiterals(text: string): string[] {
  const found = new Set<string>();
  for (const m of text.matchAll(/["'`](\/[A-Za-z][^"'`\s?]*)/g)) found.add(m[1]!.replace(/\$\{[^}]*\}/g, ":id"));
  return [...found].sort();
}

test("the extractor sees the paths the probes really use (so the doc check below cannot pass on an empty list)", () => {
  const lits = pathLiterals(source);
  for (const p of ["/notes", "/auth/login", "/auth/bootstrap", "/private/member", "/users/:id/role", "/api-keys/:id", "/webhooks/billing", "/admin/shred", "/admin/rotate-key", "/secrets", "/whoami", "/summary", "/plan"]) assert.ok(lits.includes(p), `extractor missed ${p}`);
  assert.ok(lits.length >= 18, `only ${lits.length} paths extracted`);
});

test("every path literal in probes.ts appears in docs/verify-target-contract.md", () => {
  const missing = pathLiterals(source).filter((p) => !doc.includes(`\`${p}\``));
  assert.deepEqual(missing, [], `add these to docs/verify-target-contract.md: ${missing.join(", ")}`);
});

test("every probe id appears in the contract doc", () => {
  const missing = probes.map((p) => p.id).filter((id) => !doc.includes(`\`${id}\``));
  assert.deepEqual(missing, []);
});

test("every request header and the cookie name the probes use appear in the contract doc", () => {
  const headers = new Set<string>();
  for (const m of source.matchAll(/["'`]((?:x-[a-z-]+|forwarded|authorization|sec-fetch-site|origin|cookie|set-cookie))["'`]/g)) headers.add(m[1]!);
  for (const m of source.matchAll(/[{,]\s*((?:x-[a-z-]+|forwarded|authorization|origin|cookie)):/g)) headers.add(m[1]!);
  for (const h of ["x-tenant", "x-signature", "authorization", "cookie", "origin", "sec-fetch-site"]) assert.ok(headers.has(h), `extractor missed header ${h}`);
  assert.deepEqual([...headers].filter((h) => !doc.includes(`\`${h}\``)).sort(), []);
  assert.ok(doc.includes("__Host-bk_session") && doc.includes("demo.localhost") && doc.includes("whsec_fixture"), "the doc must state the defaults");
});

test("every role, permission and manifest env name the probes use appears in the contract doc", () => {
  for (const m of source.matchAll(/permissions: \["([a-z:]+)"\]/g)) assert.ok(doc.includes(`\`${m[1]}\``), `permission ${m[1]} missing from the doc`);
  for (const r of ["owner", "admin", "member"]) assert.ok(doc.includes(`\`${r}\``), `role ${r} missing`);
  for (const e of ["BULKHEAD_VERIFY_BOOTSTRAP_TOKEN", "--persist-dir", "--route-manifest", "--cookie-name", "--host-suffix", "--webhook-secret", "verify-target.json"]) assert.ok(doc.includes(e), `${e} missing`);
});

test("each row of the doc's per-probe needs table equals the probe's declared needs (no drift)", () => {
  const section = doc.slice(doc.indexOf("## Per-probe route needs"));
  const rows = [...section.slice(0, section.indexOf("\n## ", 5) > 0 ? section.indexOf("\n## ", 5) : undefined).matchAll(/^\| `([a-z0-9-]+)` \| ([A-Z]+-\d+) \| (.+) \|$/gm)];
  assert.equal(rows.length, probes.length, "the table must have one row per probe");
  for (const p of probes) {
    const row = rows.find((r) => r[1] === p.id);
    assert.ok(row, `${p.id} has no row`);
    assert.equal(row![2], p.ruleId, `${p.id}: rule`);
    const cell = row![3]!;
    if (p.needs === undefined) assert.match(cell, /^none declared \(exempt\)$/, `${p.id}: exempt probe`);
    else assert.deepEqual([...cell.matchAll(/([A-Z]+) `([^`]+)`/g)].map((m) => `${m[1]} ${m[2]}`), p.needs.map((n) => `${n.method} ${n.path}`), `${p.id}: needs differ from the doc`);
  }
});
