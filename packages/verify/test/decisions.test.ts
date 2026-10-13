import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { decisionItems } from "@kalahroudi/bulkhead-spec";
import { mutations } from "../src/mutations.ts";
import { probes } from "../src/probes.ts";

const repo = fileURLToPath(new URL("../../../", import.meta.url));
const gates = Object.keys((JSON.parse(readFileSync(repo + "package.json", "utf8")) as { scripts: Record<string, string> }).scripts);

/** Returns why a ref does not resolve, or null when it points at something real. */
function unresolved(ref: string): string | null {
  const [kind, rest] = [ref.slice(0, ref.indexOf(":")), ref.slice(ref.indexOf(":") + 1)];
  switch (kind) {
    case "probe": return probes.some((p) => p.id === rest) ? null : "no such probe";
    case "mutation": return mutations.some((m) => m.id === rest) ? null : "no such catalog entry";
    case "gate": return gates.includes(`gate:${rest}`) ? null : "no such gate script in package.json";
    case "script": return existsSync(repo + rest) ? null : "file does not exist";
    case "test": {
      const [path, title] = rest.split("::");
      if (!path || !existsSync(repo + path)) return "test file does not exist";
      return title && !readFileSync(repo + path, "utf8").includes(title) ? `no test in ${path} mentions "${title}"` : null;
    }
    default: return "unknown ref kind";
  }
}

test("every ref a decision record cites resolves to a real probe, catalog entry, test, script or gate", () => {
  const dir = repo + "docs/decisions/";
  let checked = 0;
  for (const f of readdirSync(dir).filter((n) => /^DR-\d+.*\.md$/.test(n))) {
    for (const item of decisionItems(readFileSync(dir + f, "utf8"))?.items ?? [])
      for (const ref of item.refs) {
        checked++;
        assert.equal(unresolved(ref), null, `${f} decision ${item.number}: \`${ref}\` ${unresolved(ref)}`);
      }
  }
  assert.ok(checked > 20, "expected the records to cite their checks");
});

test("the resolver itself rejects bad refs", () => {
  for (const bad of ["probe:nope", "mutation:nope", "gate:phase99", "script:scripts/nope.ts", "test:packages/auth/test/auth.test.ts::no such title", "test:packages/nope.test.ts", "vibes:x"])
    assert.notEqual(unresolved(bad), null, bad);
  for (const good of ["probe:csrf-origin", "mutation:csrf-origin-ignored", "gate:phase4", "script:scripts/verify-mutations.ts", "test:packages/auth/test/auth.test.ts::bootstrap"])
    assert.equal(unresolved(good), null, good);
});
